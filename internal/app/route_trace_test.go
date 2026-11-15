package app

import (
	"net/netip"
	"testing"
	"time"
)

const testTraceID = 0xA104

// icmpError wraps the start of a quoted request in an ICMP error from hop.
func icmpError(t *testing.T, hop, to netip.Addr, typ byte, quoted []byte) []byte {
	t.Helper()
	var b []byte
	if hop.Is4() {
		b = make([]byte, 20+8+len(quoted))
		b[0] = 0x45
		b[2], b[3] = byte(len(b)>>8), byte(len(b))
		b[8], b[9] = 64, protoICMP
		s, d := hop.As4(), to.As4()
		copy(b[12:], s[:])
		copy(b[16:], d[:])
		b[20] = typ
		copy(b[28:], quoted)
	} else {
		b = make([]byte, 40+8+len(quoted))
		b[0] = 0x60
		b[4], b[5] = byte((8+len(quoted))>>8), byte(8+len(quoted))
		b[6], b[7] = protoICMPv6, 64
		s, d := hop.As16(), to.As16()
		copy(b[8:], s[:])
		copy(b[24:], d[:])
		b[40] = typ
		copy(b[48:], quoted)
	}
	p, ok := parsePacket(b)
	if !ok {
		t.Fatal("crafted ICMP error does not parse")
	}
	fixChecksums(b, &p)
	return b
}

func TestParseTraceReplyV4(t *testing.T) {
	src, dst, hop := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("198.51.100.7")
	req := buildICMPEchoTTL(src, dst, testTraceID, traceSeq(7, 3), 3)
	if req[8] != 3 {
		t.Fatalf("TTL not set: %d", req[8])
	}
	te := icmpError(t, hop, src, 11, req[:28])
	p, _ := parsePacket(te)
	from, seq, ok := parseTraceReply(te, &p, testTraceID)
	if run, ttl := traceUnseq(seq); !ok || from != hop || run != 7 || ttl != 3 {
		t.Fatalf("time exceeded: %v %v run=%d ttl=%d ok=%v", from, seq, run, ttl, ok)
	}
	if _, _, ok := parseTraceReply(te, &p, 0x1111); ok {
		t.Fatal("another program's probe must be ignored")
	}

	reply := append([]byte(nil), req...)
	s, d := dst.As4(), src.As4()
	copy(reply[12:], s[:])
	copy(reply[16:], d[:])
	reply[20] = 0
	rp, _ := parsePacket(reply)
	fixChecksums(reply, &rp)
	from, seq, ok = parseTraceReply(reply, &rp, testTraceID)
	if run, ttl := traceUnseq(seq); !ok || from != dst || run != 7 || ttl != 3 {
		t.Fatalf("echo reply from the destination: %v run=%d ttl=%d ok=%v", from, run, ttl, ok)
	}
}

func TestParseTraceReplyV6AndRejects(t *testing.T) {
	src, dst, hop := netip.MustParseAddr("fd00::2"), netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("2001:db8::7")
	req := buildICMPEchoTTL(src, dst, testTraceID, traceSeq(1, 5), 5)
	if req[7] != 5 {
		t.Fatalf("hop limit not set: %d", req[7])
	}
	te := icmpError(t, hop, src, 3, req[:48])
	p, _ := parsePacket(te)
	from, seq, ok := parseTraceReply(te, &p, testTraceID)
	if run, ttl := traceUnseq(seq); !ok || from != hop || run != 1 || ttl != 5 {
		t.Fatalf("v6 time exceeded: %v run=%d ttl=%d ok=%v", from, run, ttl, ok)
	}

	// destination unreachable (type 3 in v4) and a quoted non-echo are not hops
	v4src, v4dst := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("203.0.113.9")
	r4 := buildICMPEchoTTL(v4src, v4dst, testTraceID, 1, 2)
	unreach := icmpError(t, netip.MustParseAddr("198.51.100.7"), v4src, 3, r4[:28])
	up, _ := parsePacket(unreach)
	if _, _, ok := parseTraceReply(unreach, &up, testTraceID); ok {
		t.Fatal("unreachable must not count as a hop")
	}
	udp := make([]byte, 28)
	udp[0], udp[9] = 0x45, protoUDP
	quotedUDP := icmpError(t, netip.MustParseAddr("198.51.100.7"), v4src, 11, udp)
	qp, _ := parsePacket(quotedUDP)
	if _, _, ok := parseTraceReply(quotedUDP, &qp, testTraceID); ok {
		t.Fatal("a quoted UDP packet is not our echo")
	}
}

func TestTrimHopsStopsAtDestinationAndDropsTrailingSilence(t *testing.T) {
	ms := time.Millisecond
	a, b, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("203.0.113.9")
	hops := []Hop{{1, a, ms}, {2, netip.Addr{}, 0}, {3, dst, 9 * ms}, {4, b, 10 * ms}}
	if got := trimHops(hops, dst); len(got) != 3 || got[2].Addr != dst {
		t.Fatalf("stop at destination: %v", got)
	}
	silent := []Hop{{1, a, ms}, {2, b, 2 * ms}, {3, netip.Addr{}, 0}, {4, netip.Addr{}, 0}}
	if got := trimHops(silent, dst); len(got) != 2 {
		t.Fatalf("trailing silence kept: %v", got)
	}
	if got := trimHops([]Hop{{1, netip.Addr{}, 0}}, dst); len(got) != 0 {
		t.Fatalf("all silent: %v", got)
	}
}

func TestTraceSeqRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		run uint8
		ttl int
	}{{0, 1}, {255, 20}, {7, 3}} {
		if run, ttl := traceUnseq(traceSeq(tc.run, tc.ttl)); run != tc.run || ttl != tc.ttl {
			t.Errorf("%v -> run=%d ttl=%d", tc, run, ttl)
		}
	}
}
