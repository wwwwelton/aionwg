package app

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ProtoVersion    = 1
	HeaderLen       = 18
	TagLen          = 16
	DataFixedLen    = 4 + 8 // flow (4) + seq (8)
	MaxDatagramSize = 65507
	RelayBit        = uint64(1) << 63
)

type PacketKind uint8

const (
	KindData  PacketKind = 1
	KindPing  PacketKind = 2
	KindPong  PacketKind = 3
	KindClose PacketKind = 4
)

var (
	ErrTruncated = errors.New("datagram too short")
	ErrVersion   = errors.New("unsupported protocol version")
	ErrKind      = errors.New("unknown packet kind")
	ErrAuth      = errors.New("authentication failed")
	ErrAddress   = errors.New("malformed address")
	ErrTooLarge  = errors.New("payload too large")
)

type PacketHeader struct {
	Kind    PacketKind
	Session uint64
	Counter uint64
}

func (h PacketHeader) Encode(out []byte) {
	out[0] = ProtoVersion
	out[1] = byte(h.Kind)
	binary.LittleEndian.PutUint64(out[2:10], h.Session)
	binary.LittleEndian.PutUint64(out[10:18], h.Counter)
}

func DecodeHeader(buf []byte) (PacketHeader, error) {
	if len(buf) < HeaderLen+TagLen {
		return PacketHeader{}, ErrTruncated
	}
	if buf[0] != ProtoVersion {
		return PacketHeader{}, ErrVersion
	}
	k := PacketKind(buf[1])
	if k < KindData || k > KindClose {
		return PacketHeader{}, ErrKind
	}
	return PacketHeader{
		Kind:    k,
		Session: binary.LittleEndian.Uint64(buf[2:10]),
		Counter: binary.LittleEndian.Uint64(buf[10:18]),
	}, nil
}

type PingBody struct {
	Path   uint16
	Probe  uint32
	SentUS uint64
}

func (p PingBody) Encode(out []byte) {
	binary.LittleEndian.PutUint16(out[0:2], p.Path)
	binary.LittleEndian.PutUint32(out[2:6], p.Probe)
	binary.LittleEndian.PutUint64(out[6:14], p.SentUS)
}

func DecodePingBody(buf []byte) (PingBody, error) {
	if len(buf) != 14 {
		return PingBody{}, ErrTruncated
	}
	return PingBody{
		Path:   binary.LittleEndian.Uint16(buf[0:2]),
		Probe:  binary.LittleEndian.Uint32(buf[2:6]),
		SentUS: binary.LittleEndian.Uint64(buf[6:14]),
	}, nil
}

type DataBody struct {
	Flow    uint32
	Seq     uint64
	Peer    netip.AddrPort
	Payload []byte
}

func EncodeAddr(ap netip.AddrPort, out []byte) int {
	addr := ap.Addr()
	if addr.Is4() {
		out[0] = 4
		b4 := addr.As4()
		copy(out[1:5], b4[:])
		binary.BigEndian.PutUint16(out[5:7], ap.Port())
		return 7
	}
	out[0] = 6
	b6 := addr.As16()
	copy(out[1:17], b6[:])
	binary.BigEndian.PutUint16(out[17:19], ap.Port())
	return 19
}

func DecodeAddr(buf []byte) (netip.AddrPort, int, error) {
	if len(buf) < 1 {
		return netip.AddrPort{}, 0, ErrAddress
	}
	switch buf[0] {
	case 4:
		if len(buf) < 7 {
			return netip.AddrPort{}, 0, ErrAddress
		}
		ip, _ := netip.AddrFromSlice(buf[1:5])
		port := binary.BigEndian.Uint16(buf[5:7])
		return netip.AddrPortFrom(ip, port), 7, nil
	case 6:
		if len(buf) < 19 {
			return netip.AddrPort{}, 0, ErrAddress
		}
		ip, _ := netip.AddrFromSlice(buf[1:17])
		port := binary.BigEndian.Uint16(buf[17:19])
		return netip.AddrPortFrom(ip, port), 19, nil
	default:
		return netip.AddrPort{}, 0, ErrAddress
	}
}

// SessionKeys manages key derivation via BLAKE3
type PinglessSessionKeys struct {
	master [32]byte
}

func NewPinglessSessionKeys(psk string) *PinglessSessionKeys {
	kdf := blake3.NewDeriveKey("openlag v1 master key")
	_, _ = kdf.WriteString(psk)
	var master [32]byte
	_, _ = kdf.Digest().Read(master[:])
	return &PinglessSessionKeys{master: master}
}

func (sk *PinglessSessionKeys) Session(session uint64, relaySide bool) (*PacketCipher, error) {
	h, err := blake3.NewKeyed(sk.master[:])
	if err != nil {
		return nil, err
	}
	var sessBytes [8]byte
	binary.LittleEndian.PutUint64(sessBytes[:], session)
	_, _ = h.Write(sessBytes[:])
	var key [32]byte
	_, _ = h.Digest().Read(key[:])

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	var randBytes [8]byte
	_, _ = rand.Read(randBytes[:])
	start := binary.LittleEndian.Uint64(randBytes[:]) & ((1 << 62) - 1)
	if relaySide {
		start |= RelayBit
	}

	return &PacketCipher{
		aead:      aead,
		session:   session,
		counter:   start,
		relaySide: relaySide,
	}, nil
}

type PacketCipher struct {
	aead      cipher.AEAD
	session   uint64
	counter   uint64
	relaySide bool
	mu        sync.Mutex
}

func (c *PacketCipher) SessionID() uint64 {
	return c.session
}

func makeNonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n
}

func (c *PacketCipher) SealData(d *DataBody, out []byte) ([]byte, error) {
	c.mu.Lock()
	cnt := c.counter
	c.counter++
	c.mu.Unlock()

	hdr := PacketHeader{
		Kind:    KindData,
		Session: c.session,
		Counter: cnt,
	}

	// Payload layout: Header(18) + Flow(4) + Seq(8) + Addr(7 or 19) + Data...
	plain := out[:HeaderLen]
	hdr.Encode(plain)

	var body [DataFixedLen + 19]byte
	binary.LittleEndian.PutUint32(body[0:4], d.Flow)
	binary.LittleEndian.PutUint64(body[4:12], d.Seq)
	addrLen := EncodeAddr(d.Peer, body[12:])
	bodyLen := DataFixedLen + addrLen

	plain = append(plain, body[:bodyLen]...)
	plain = append(plain, d.Payload...)

	if len(plain)+TagLen > MaxDatagramSize {
		return nil, ErrTooLarge
	}

	nonce := makeNonce(cnt)
	// aead.Seal appends ciphertext + 16-byte tag to the dst slice
	sealed := c.aead.Seal(plain[:HeaderLen], nonce, plain[HeaderLen:], plain[:HeaderLen])
	return sealed, nil
}

func (c *PacketCipher) SealPing(p PingBody, out []byte) ([]byte, error) {
	return c.sealPingWithKind(KindPing, p, out)
}

func (c *PacketCipher) SealPong(p PingBody, out []byte) ([]byte, error) {
	return c.sealPingWithKind(KindPong, p, out)
}

func (c *PacketCipher) sealPingWithKind(k PacketKind, p PingBody, out []byte) ([]byte, error) {
	c.mu.Lock()
	cnt := c.counter
	c.counter++
	c.mu.Unlock()

	hdr := PacketHeader{
		Kind:    k,
		Session: c.session,
		Counter: cnt,
	}

	plain := out[:HeaderLen]
	hdr.Encode(plain)

	var body [14]byte
	p.Encode(body[:])
	plain = append(plain, body[:]...)

	nonce := makeNonce(cnt)
	sealed := c.aead.Seal(plain[:HeaderLen], nonce, plain[HeaderLen:], plain[:HeaderLen])
	return sealed, nil
}

func (c *PacketCipher) SealClose(flowID uint32, out []byte) ([]byte, error) {
	c.mu.Lock()
	cnt := c.counter
	c.counter++
	c.mu.Unlock()

	hdr := PacketHeader{
		Kind:    KindClose,
		Session: c.session,
		Counter: cnt,
	}
	plain := out[:HeaderLen]
	hdr.Encode(plain)

	var body [4]byte
	binary.LittleEndian.PutUint32(body[:], flowID)
	plain = append(plain, body[:]...)

	nonce := makeNonce(cnt)
	sealed := c.aead.Seal(plain[:HeaderLen], nonce, plain[HeaderLen:], plain[:HeaderLen])
	return sealed, nil
}

func (c *PacketCipher) Open(buf []byte) (PacketHeader, PacketKind, []byte, error) {
	hdr, err := DecodeHeader(buf)
	if err != nil {
		return PacketHeader{}, 0, nil, err
	}
	if hdr.Session != c.session {
		return PacketHeader{}, 0, nil, ErrAuth
	}
	// Counters must match sender's half
	if (hdr.Counter&RelayBit != 0) == c.relaySide {
		return PacketHeader{}, 0, nil, ErrAuth
	}

	nonce := makeNonce(hdr.Counter)
	aad := buf[:HeaderLen]
	ciphertextWithTag := buf[HeaderLen:]

	plain, err := c.aead.Open(buf[:HeaderLen], nonce, ciphertextWithTag, aad)
	if err != nil {
		return PacketHeader{}, 0, nil, ErrAuth
	}
	return hdr, hdr.Kind, plain[HeaderLen:], nil
}

// SeqWindow is a sliding window of 1024 sequence numbers for deduplication
const (
	SeqWords = 16
	SeqSize  = uint64(SeqWords * 64)
)

type PinglessSeqWindow struct {
	highest uint64
	bits    [SeqWords]uint64
}

func (w *PinglessSeqWindow) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.highest {
		if seq-w.highest >= SeqSize {
			w.bits = [SeqWords]uint64{}
		} else {
			for s := w.highest + 1; s < seq; s++ {
				w.clear(s)
			}
		}
		w.highest = seq
		w.set(seq)
		return true
	}
	if w.highest-seq >= SeqSize || w.get(seq) {
		return false
	}
	w.set(seq)
	return true
}

func slot(seq uint64) (int, uint64) {
	i := seq % SeqSize
	return int(i / 64), uint64(1) << (i % 64)
}

func (w *PinglessSeqWindow) get(seq uint64) bool {
	word, bit := slot(seq)
	return (w.bits[word] & bit) != 0
}

func (w *PinglessSeqWindow) set(seq uint64) {
	word, bit := slot(seq)
	w.bits[word] |= bit
}

func (w *PinglessSeqWindow) clear(seq uint64) {
	word, bit := slot(seq)
	w.bits[word] &= ^bit
}
