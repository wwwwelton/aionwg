package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// verify checks IPv4 header + L4 checksums using an independent fold.
func verifyChecksums(t *testing.T, b []byte) {
	t.Helper()
	p, ok := parsePacket(b)
	if !ok {
		t.Fatal("parse failed")
	}
	if !p.v6 && csumFold(csumAdd(0, b[:p.ipHdr])) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}
	l4 := b[p.l4:pktLen(b, &p)]
	var sum uint32
	if p.proto == protoICMP {
		sum = csumAdd(0, l4)
	} else {
		if p.v6 {
			sum = csumAdd(0, b[8:40])
		} else {
			sum = csumAdd(0, b[12:20])
		}
		sum += uint32(p.proto) + uint32(len(l4))
		sum = csumAdd(sum, l4)
	}
	if csumFold(sum) != 0 {
		t.Fatalf("bad L4 checksum proto %d", p.proto)
	}
}

func mkTCPSyn(src, dst string, sport, dport, mss uint16) []byte {
	b := make([]byte, 20+24)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 128
	b[9] = protoTCP
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	t := b[20:]
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	t[12] = 6 << 4 // 24 bytes
	t[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(t[14:], 64240)
	t[20], t[21] = 2, 4
	binary.BigEndian.PutUint16(t[22:], mss)
	p, _ := parsePacket(b)
	fixChecksums(b, &p)
	return b
}

func TestSNATAndMSS(t *testing.T) {
	b := mkTCPSyn("192.168.1.50", "203.0.113.7", 50123, 443, 1460)
	verifyChecksums(t, b)
	p, ok := parsePacket(b)
	if !ok || !p.tcpSYN || p.srcPort != 50123 || p.dstPort != 443 {
		t.Fatalf("parse: %+v", p)
	}
	setSrc(b, &p, netip.MustParseAddr("10.66.66.2"))
	if !clampMSS(b, &p, 1380) {
		t.Fatal("mss not clamped")
	}
	fixChecksums(b, &p)
	verifyChecksums(t, b)
	p2, _ := parsePacket(b)
	if p2.src.String() != "10.66.66.2" {
		t.Fatal("src not rewritten")
	}
	if got := binary.BigEndian.Uint16(b[20+22:]); got != 1380 {
		t.Fatalf("mss %d", got)
	}
	// DNAT back
	setDst(b, &p2, netip.MustParseAddr("192.168.1.99"))
	fixChecksums(b, &p2)
	verifyChecksums(t, b)
	if clampMSS(b, &p2, 1500) {
		t.Fatal("should not raise MSS")
	}
}

func TestUDPv4v6(t *testing.T) {
	// IPv4 UDP
	b := make([]byte, 20+8+5)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = protoUDP
	copy(b[12:], []byte{192, 168, 0, 2})
	copy(b[16:], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(b[20:], 6000)
	binary.BigEndian.PutUint16(b[22:], 7000)
	binary.BigEndian.PutUint16(b[24:], 13)
	copy(b[28:], "hello")
	p, ok := parsePacket(b)
	if !ok || p.proto != protoUDP {
		t.Fatal("udp parse")
	}
	setSrc(b, &p, netip.MustParseAddr("10.0.0.2"))
	fixChecksums(b, &p)
	verifyChecksums(t, b)

	// IPv6 UDP
	b6 := make([]byte, 40+8+3)
	b6[0] = 0x60
	binary.BigEndian.PutUint16(b6[4:], 11)
	b6[6] = protoUDP
	s := netip.MustParseAddr("fd00::2").As16()
	d := netip.MustParseAddr("2001:db8::1").As16()
	copy(b6[8:], s[:])
	copy(b6[24:], d[:])
	binary.BigEndian.PutUint16(b6[40:], 1)
	binary.BigEndian.PutUint16(b6[42:], 2)
	binary.BigEndian.PutUint16(b6[44:], 11)
	p6, ok := parsePacket(b6)
	if !ok || !p6.v6 {
		t.Fatal("v6 parse")
	}
	setSrc(b6, &p6, netip.MustParseAddr("fd00::99"))
	fixChecksums(b6, &p6)
	verifyChecksums(t, b6)
}

func TestICMPEcho(t *testing.T) {
	b := buildICMPEcho(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"), 0xA102, 7)
	verifyChecksums(t, b)
	// turn into reply
	p, _ := parsePacket(b)
	b[p.l4] = 0
	id, seq, ok := parseICMPEchoReply(b, &p)
	if !ok || id != 0xA102 || seq != 7 {
		t.Fatal("echo reply parse")
	}
	b6 := buildICMPEcho(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1"), 1, 2)
	verifyChecksums(t, b6)
}

func TestFragmentPassthrough(t *testing.T) {
	b := mkTCPSyn("1.1.1.1", "2.2.2.2", 1, 2, 1460)
	b[6] = 0x20 // MF
	if _, ok := parsePacket(b); ok {
		t.Fatal("fragments must not be captured")
	}
}

// The WinDivert capture buffer is 65535 bytes, far larger than the packet.
// A header claiming a total length too short for its L4 header must be
// rejected: otherwise fixChecksums/clampMSS index past pktLen() and panic.
func TestParseRejectsTruncatedInLargeBuffer(t *testing.T) {
	buf := make([]byte, 65535)

	v4 := func(proto byte, total int) []byte {
		b := append([]byte(nil), buf...)
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:], uint16(total))
		b[9] = proto
		return b
	}
	v6 := func(proto byte, payload int) []byte {
		b := append([]byte(nil), buf...)
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], uint16(payload))
		b[6] = proto
		return b
	}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"v4 tcp total=ihl", v4(protoTCP, 20)},
		{"v4 tcp total<l4+20", v4(protoTCP, 39)},
		{"v4 udp total<l4+8", v4(protoUDP, 27)},
		{"v4 icmp total<l4+8", v4(protoICMP, 27)},
		{"v6 tcp payload=0", v6(protoTCP, 0)},
		{"v6 tcp payload<20", v6(protoTCP, 19)},
		{"v6 udp payload<8", v6(protoUDP, 7)},
		{"v6 payload beyond buffer", v6(protoUDP, 65535)},
	}
	for _, c := range cases {
		if _, ok := parsePacket(c.pkt); ok {
			t.Errorf("%s: truncated packet accepted", c.name)
		}
	}

	// Minimal valid packets must still parse inside the large buffer, and the
	// helpers that trusted the parser must stay within pktLen().
	good := v4(protoUDP, 28)
	p, ok := parsePacket(good)
	if !ok || pktLen(good, &p) != 28 {
		t.Fatalf("minimal v4 udp rejected: ok=%v", ok)
	}
	fixChecksums(good, &p)
	syn := mkTCPSyn("192.168.1.50", "203.0.113.7", 50123, 443, 1460)
	big := append(append([]byte(nil), syn...), make([]byte, 65535-len(syn))...)
	sp, ok := parsePacket(big)
	if !ok || !clampMSS(big, &sp, 1200) {
		t.Fatal("MSS clamp must work on a packet inside a larger buffer")
	}
	if got := binary.BigEndian.Uint16(big[sp.l4+22:]); got != 1200 {
		t.Fatalf("MSS = %d, want 1200", got)
	}
}

const sampleConf = `
[Interface]
# comentário
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.66.66.2/24, fd42:42:42::2/64
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	if c.MTU != 1380 || len(c.Addresses) != 2 || len(c.Peers) != 1 {
		t.Fatalf("%+v", c)
	}
	a4, ok := c.Addr(false)
	if !ok || a4.String() != "10.66.66.2" {
		t.Fatal("addr4")
	}
	if !c.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("allowed")
	}
	ep, err := ResolveEndpoint(c.Peers[0].Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	u := c.UAPI([]netip.AddrPort{ep})
	for _, want := range []string{"private_key=c809f3e5", "endpoint=203.0.113.10:51820",
		"persistent_keepalive_interval=25", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0", "preshared_key="} {
		if !strings.Contains(u, want) {
			t.Fatalf("UAPI missing %q:\n%s", want, u)
		}
	}
	if _, err := ParseConfig("[Interface]\nAddress=10.0.0.2/32\n"); err == nil {
		t.Fatal("expected error")
	}
}
