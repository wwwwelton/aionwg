package main

// Packet parsing, address rewriting, checksum recomputation and TCP MSS
// clamping. Platform independent so it can be unit-tested anywhere.

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

const maxPktBuf = 65535

// pktPool recycles packet buffers across capture, segmentation, latestQueue
// and splitTun so the per-packet hot path does not allocate on the heap.
// Storing *[maxPktBuf]byte in sync.Pool is pointer-sized and avoids interface
// boxing allocations on Put.
var pktPool = sync.Pool{
	New: func() any { return new([maxPktBuf]byte) },
}

func getPktBuf(n int) []byte {
	if n > maxPktBuf {
		return make([]byte, n)
	}
	return pktPool.Get().(*[maxPktBuf]byte)[:n]
}

func clonePktBuf(src []byte) []byte {
	dst := getPktBuf(len(src))
	copy(dst, src)
	return dst
}

func putPktBuf(b []byte) {
	if cap(b) != maxPktBuf {
		return
	}
	pktPool.Put((*[maxPktBuf]byte)(b[:maxPktBuf]))
}

// pktInfo describes the parts of an IP packet we care about.
type pktInfo struct {
	v6      bool
	proto   uint8
	ipHdr   int // IP header length (incl. IPv6 base header only)
	l4      int // offset of the L4 header
	src     netip.Addr
	dst     netip.Addr
	srcPort uint16
	dstPort uint16
	tcpSYN  bool
	frag    bool // IPv4 fragment (non-first or MF set)
}

// parsePacket parses an IPv4/IPv6 packet. Returns ok=false for anything we
// don't know how to handle (those packets are passed through untouched).
func parsePacket(b []byte) (p pktInfo, ok bool) {
	if len(b) < 1 {
		return p, false
	}
	// n is the real packet length (IPv4 total length / IPv6 payload+40).
	// Every transport check below uses n, never len(b): the capture buffer is
	// larger than the packet, so a truncated header would otherwise pass here
	// and later index past pktLen() in fixChecksums/clampMSS/segmentTCP.
	var n int
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, false
		}
		n = int(binary.BigEndian.Uint16(b[2:4]))
		if n < ihl || n > len(b) {
			return p, false
		}
		fragField := binary.BigEndian.Uint16(b[6:8])
		p.frag = fragField&0x3fff != 0 // MF flag or offset != 0
		p.proto = b[9]
		p.ipHdr = ihl
		p.l4 = ihl
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		if len(b) < 40 {
			return p, false
		}
		n = 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			return p, false
		}
		p.v6 = true
		p.proto = b[6] // extension headers are not followed; unknown -> passthrough
		p.ipHdr = 40
		p.l4 = 40
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
	default:
		return p, false
	}
	switch p.proto {
	case protoTCP:
		if p.frag || n < p.l4+20 {
			return p, false
		}
		p.srcPort = binary.BigEndian.Uint16(b[p.l4:])
		p.dstPort = binary.BigEndian.Uint16(b[p.l4+2:])
		p.tcpSYN = b[p.l4+13]&0x02 != 0
	case protoUDP:
		if p.frag || n < p.l4+8 {
			return p, false
		}
		p.srcPort = binary.BigEndian.Uint16(b[p.l4:])
		p.dstPort = binary.BigEndian.Uint16(b[p.l4+2:])
	case protoICMP, protoICMPv6:
		if n < p.l4+8 {
			return p, false
		}
	default:
		return p, false
	}
	return p, true
}

func setSrc(b []byte, p *pktInfo, a netip.Addr) {
	if p.v6 {
		s := a.As16()
		copy(b[8:24], s[:])
	} else {
		s := a.As4()
		copy(b[12:16], s[:])
	}
	p.src = a
}

func setDst(b []byte, p *pktInfo, a netip.Addr) {
	if p.v6 {
		s := a.As16()
		copy(b[24:40], s[:])
	} else {
		s := a.As4()
		copy(b[16:20], s[:])
	}
	p.dst = a
}

// pktLen returns the real length of the packet (IPv4 total length / IPv6 payload+40).
func pktLen(b []byte, p *pktInfo) int {
	if p.v6 {
		n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			n = len(b)
		}
		return n
	}
	return int(binary.BigEndian.Uint16(b[2:4]))
}

func csumAdd(sum uint32, b []byte) uint32 {
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	return sum
}

func csumFold(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// fixChecksums recomputes IPv4 header and L4 checksums in place.
func fixChecksums(b []byte, p *pktInfo) {
	n := pktLen(b, p)
	b = b[:n]
	if !p.v6 {
		b[10], b[11] = 0, 0
		binary.BigEndian.PutUint16(b[10:12], csumFold(csumAdd(0, b[:p.ipHdr])))
	}
	l4 := b[p.l4:]
	var off int
	switch p.proto {
	case protoTCP:
		off = 16
	case protoUDP:
		off = 6
	case protoICMP:
		l4[2], l4[3] = 0, 0
		binary.BigEndian.PutUint16(l4[2:4], csumFold(csumAdd(0, l4)))
		return
	case protoICMPv6:
		off = 2
	default:
		return
	}
	l4[off], l4[off+1] = 0, 0
	var sum uint32
	if p.v6 {
		sum = csumAdd(sum, b[8:40])
	} else {
		sum = csumAdd(sum, b[12:20])
	}
	sum += uint32(p.proto)
	sum += uint32(len(l4))
	sum = csumAdd(sum, l4)
	c := csumFold(sum)
	if c == 0 && p.proto == protoUDP {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(l4[off:off+2], c)
}

// clampMSS lowers the TCP MSS option of a SYN / SYN-ACK to maxMSS.
// Returns true if the packet was modified (checksum must be recomputed).
func clampMSS(b []byte, p *pktInfo, maxMSS uint16) bool {
	if p.proto != protoTCP || !p.tcpSYN {
		return false
	}
	t := b[p.l4:pktLen(b, p)]
	doff := int(t[12]>>4) * 4
	if doff < 20 || doff > len(t) {
		return false
	}
	opts := t[20:doff]
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		if kind == 2 && l == 4 {
			mss := binary.BigEndian.Uint16(opts[i+2:])
			if mss > maxMSS {
				binary.BigEndian.PutUint16(opts[i+2:], maxMSS)
				return true
			}
			return false
		}
		i += l
	}
	return false
}

// buildICMPEcho builds an ICMP/ICMPv6 echo request.
func buildICMPEcho(src, dst netip.Addr, id, seq uint16) []byte {
	payload := []byte("aionwg-ping-0123456789abcdef")
	if dst.Is4() {
		b := make([]byte, 20+8+len(payload))
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		b[8] = 64
		b[9] = protoICMP
		s, d := src.As4(), dst.As4()
		copy(b[12:], s[:])
		copy(b[16:], d[:])
		b[20] = 8 // echo request
		binary.BigEndian.PutUint16(b[24:], id)
		binary.BigEndian.PutUint16(b[26:], seq)
		copy(b[28:], payload)
		p, _ := parsePacket(b)
		fixChecksums(b, &p)
		return b
	}
	b := make([]byte, 40+8+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	b[6] = protoICMPv6
	b[7] = 64
	s, d := src.As16(), dst.As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	b[40] = 128 // echo request
	binary.BigEndian.PutUint16(b[44:], id)
	binary.BigEndian.PutUint16(b[46:], seq)
	copy(b[48:], payload)
	p, _ := parsePacket(b)
	fixChecksums(b, &p)
	return b
}

// parseICMPEchoReply returns id/seq if b is an echo reply.
func parseICMPEchoReply(b []byte, p *pktInfo) (id, seq uint16, ok bool) {
	t := b[p.l4:]
	if (p.proto == protoICMP && t[0] == 0) || (p.proto == protoICMPv6 && t[0] == 129) {
		return binary.BigEndian.Uint16(t[4:]), binary.BigEndian.Uint16(t[6:]), true
	}
	return 0, 0, false
}

// segmentTCP splits a TCP packet bigger than mtu (Windows LSO "super-packets")
// into MTU-sized segments. Returns nil if no split is needed.
func segmentTCP(b []byte, p *pktInfo, mtu int) [][]byte {
	n := pktLen(b, p)
	if p.proto != protoTCP || n <= mtu {
		return nil
	}
	t := b[p.l4:n]
	doff := int(t[12]>>4) * 4
	if doff < 20 || doff > len(t) {
		return nil
	}
	hdr := b[:p.l4+doff]
	payload := b[p.l4+doff : n]
	chunk := mtu - len(hdr)
	if chunk < 64 || len(payload) == 0 {
		return nil
	}
	seq := binary.BigEndian.Uint32(t[4:])
	flags := t[13]
	var id uint16
	if !p.v6 {
		id = binary.BigEndian.Uint16(b[4:6])
	}
	var out [][]byte
	for off, i := 0, 0; off < len(payload); off, i = off+chunk, i+1 {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		seg := getPktBuf(len(hdr) + end - off)
		copy(seg, hdr)
		copy(seg[len(hdr):], payload[off:end])
		st := seg[p.l4:]
		binary.BigEndian.PutUint32(st[4:], seq+uint32(off))
		f := flags
		if end < len(payload) {
			f &^= 0x01 | 0x08 // FIN and PSH only on the last segment
		}
		if off > 0 {
			f &^= 0x80 // CWR only on the first
		}
		st[13] = f
		if p.v6 {
			binary.BigEndian.PutUint16(seg[4:], uint16(len(seg)-40))
		} else {
			binary.BigEndian.PutUint16(seg[2:], uint16(len(seg)))
			binary.BigEndian.PutUint16(seg[4:], id+uint16(i))
		}
		sp := *p
		fixChecksums(seg, &sp)
		out = append(out, seg)
	}
	return out
}

// parseICMPError finds the original packet quoted inside an ICMP error
// (unreachable / fragmentation needed / packet too big / time exceeded).
func parseICMPError(b []byte, p *pktInfo) (off int, inner pktInfo, ok bool) {
	n := pktLen(b, p)
	if n < p.l4+8 {
		return 0, inner, false
	}
	typ := b[p.l4]
	switch {
	case p.proto == protoICMP && (typ == 3 || typ == 11 || typ == 12):
	case p.proto == protoICMPv6 && typ >= 1 && typ <= 4:
	default:
		return 0, inner, false
	}
	off = p.l4 + 8
	q := b[off:n]
	if len(q) < 1 {
		return 0, inner, false
	}
	switch q[0] >> 4 {
	case 4:
		if len(q) < 20 {
			return 0, inner, false
		}
		ihl := int(q[0]&0x0f) * 4
		if ihl < 20 || len(q) < ihl+4 {
			return 0, inner, false
		}
		inner.proto, inner.ipHdr, inner.l4 = q[9], ihl, ihl
		inner.src = netip.AddrFrom4([4]byte(q[12:16]))
		inner.dst = netip.AddrFrom4([4]byte(q[16:20]))
	case 6:
		if len(q) < 44 {
			return 0, inner, false
		}
		inner.v6, inner.proto, inner.ipHdr, inner.l4 = true, q[6], 40, 40
		inner.src = netip.AddrFrom16([16]byte(q[8:24]))
		inner.dst = netip.AddrFrom16([16]byte(q[24:40]))
	default:
		return 0, inner, false
	}
	if inner.proto != protoTCP && inner.proto != protoUDP {
		return 0, inner, false
	}
	inner.srcPort = binary.BigEndian.Uint16(q[inner.l4:])
	inner.dstPort = binary.BigEndian.Uint16(q[inner.l4+2:])
	return off, inner, true
}

// rewriteICMPError points an ICMP error from the tunnel back at the real
// local address: outer destination and the quoted packet's source.
func rewriteICMPError(b []byte, p *pktInfo, off int, inner *pktInfo, local netip.Addr) {
	q := b[off:]
	setSrc(q, inner, local)
	if !inner.v6 {
		q[10], q[11] = 0, 0
		binary.BigEndian.PutUint16(q[10:12], csumFold(csumAdd(0, q[:inner.ipHdr])))
	}
	setDst(b, p, local)
	fixChecksums(b, p)
}

// buildTCPResetV6 answers an IPv6 TCP SYN with RST+ACK, so apps give up on
// IPv6 immediately and fall back to IPv4 (which goes through the tunnel).
func buildTCPResetV6(b []byte, p *pktInfo) []byte {
	if !p.v6 || p.proto != protoTCP {
		return nil
	}
	n := pktLen(b, p)
	t := b[p.l4:n]
	if len(t) < 20 {
		return nil
	}
	doff := int(t[12]>>4) * 4
	if doff < 20 || doff > len(t) {
		return nil
	}
	seq := binary.BigEndian.Uint32(t[4:])
	ack := seq + uint32(len(t)-doff)
	if t[13]&0x02 != 0 {
		ack++ // SYN counts as one
	}
	r := make([]byte, 60)
	r[0] = 0x60
	binary.BigEndian.PutUint16(r[4:], 20)
	r[6], r[7] = protoTCP, 64
	s, d := p.dst.As16(), p.src.As16()
	copy(r[8:], s[:])
	copy(r[24:], d[:])
	binary.BigEndian.PutUint16(r[40:], p.dstPort)
	binary.BigEndian.PutUint16(r[42:], p.srcPort)
	binary.BigEndian.PutUint32(r[48:], ack)
	r[52] = 5 << 4
	r[53] = 0x14 // RST|ACK
	rp, _ := parsePacket(r)
	fixChecksums(r, &rp)
	return r
}
