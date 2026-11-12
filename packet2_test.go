package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSegmentTCP(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789"), 1000) // 10 000 bytes (LSO)
	b := mkTCP("192.168.0.10", "203.0.113.5", 50000, 443, 7000, 0x18|0x01, payload)
	p, ok := parsePacket(b)
	if !ok {
		t.Fatal("parse")
	}
	segs := segmentTCP(b, &p, 1420)
	if len(segs) != 8 { // 1380 bytes per segment
		t.Fatalf("got %d segments", len(segs))
	}
	var rebuilt []byte
	for i, s := range segs {
		if len(s) > 1420 {
			t.Fatal("segment too big")
		}
		verifyChecksums(t, s)
		sp, _ := parsePacket(s)
		seq := binary.BigEndian.Uint32(s[sp.l4+4:])
		if seq != 7000+uint32(len(rebuilt)) {
			t.Fatalf("seg %d seq %d", i, seq)
		}
		fl := s[sp.l4+13]
		last := i == len(segs)-1
		if (fl&0x01 != 0) != last || (fl&0x08 != 0) != last {
			t.Fatalf("seg %d flags %x", i, fl)
		}
		rebuilt = append(rebuilt, s[sp.l4+20:]...)
	}
	if !bytes.Equal(rebuilt, payload) {
		t.Fatal("payload mismatch")
	}
	small := mkTCP("1.1.1.1", "2.2.2.2", 1, 2, 0, 0x10, []byte("hi"))
	sp, _ := parsePacket(small)
	if segmentTCP(small, &sp, 1420) != nil {
		t.Fatal("small packet must not be split")
	}
}

func TestPktPoolCloneAndPutZeroAllocs(t *testing.T) {
	src := bytes.Repeat([]byte{0x42}, 1400)
	putPktBuf(clonePktBuf(src)) // warm pool
	allocs := testing.AllocsPerRun(100, func() {
		b := clonePktBuf(src)
		putPktBuf(b)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs/op on pooled packet clone+put, got %v", allocs)
	}
}

func TestICMPErrorRewrite(t *testing.T) {
	// original packet as the remote router saw it (src = tunnel IP)
	orig := mkTCP("10.77.78.2", "203.0.113.5", 50000, 443, 1, 0x10, bytes.Repeat([]byte{1}, 100))
	quoted := orig[:28]
	b := make([]byte, 20+8+len(quoted))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, protoICMP
	copy(b[12:], []byte{198, 51, 100, 1})
	copy(b[16:], []byte{10, 77, 78, 2})
	b[20], b[21] = 3, 4 // frag needed
	binary.BigEndian.PutUint16(b[26:], 1400)
	copy(b[28:], quoted)
	p, _ := parsePacket(b)
	fixChecksums(b, &p)

	off, inner, ok := parseICMPError(b, &p)
	if !ok || inner.srcPort != 50000 || inner.proto != protoTCP {
		t.Fatalf("parse %v %+v", ok, inner)
	}
	local := netip.MustParseAddr("192.168.0.10")
	rewriteICMPError(b, &p, off, &inner, local)
	verifyChecksums(t, b)
	p2, _ := parsePacket(b)
	if p2.dst != local {
		t.Fatal("outer dst")
	}
	if netip.AddrFrom4([4]byte(b[off+12:off+16])) != local {
		t.Fatal("inner src")
	}
	if csumFold(csumAdd(0, b[off:off+20])) != 0 {
		t.Fatal("inner ip checksum")
	}
}

func TestTCPResetV6(t *testing.T) {
	syn := make([]byte, 40+20)
	syn[0] = 0x60
	binary.BigEndian.PutUint16(syn[4:], 20)
	syn[6], syn[7] = protoTCP, 64
	s := netip.MustParseAddr("2804:14c::10").As16()
	d := netip.MustParseAddr("2600:1f1e::5").As16()
	copy(syn[8:], s[:])
	copy(syn[24:], d[:])
	binary.BigEndian.PutUint16(syn[40:], 51000)
	binary.BigEndian.PutUint16(syn[42:], 443)
	binary.BigEndian.PutUint32(syn[44:], 1000)
	syn[52], syn[53] = 5<<4, 0x02
	p, ok := parsePacket(syn)
	if !ok {
		t.Fatal("parse")
	}
	r := buildTCPResetV6(syn, &p)
	verifyChecksums(t, r)
	rp, _ := parsePacket(r)
	if rp.src != p.dst || rp.dst != p.src || rp.srcPort != 443 || rp.dstPort != 51000 {
		t.Fatalf("%+v", rp)
	}
	if binary.BigEndian.Uint32(r[48:]) != 1001 || r[53] != 0x14 {
		t.Fatal("ack/flags")
	}
}
