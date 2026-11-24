package app

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestBuildInboundUDPPacket(t *testing.T) {
	src := netip.MustParseAddrPort("198.51.100.1:27015")
	dst := netip.MustParseAddrPort("192.168.1.100:54321")
	payload := []byte("game server packet")

	pkt, info := BuildInboundUDPPacket(src, dst, payload)
	if len(pkt) != 20+8+len(payload) {
		t.Fatalf("unexpected len: %d", len(pkt))
	}

	parsed, ok := parsePacket(pkt)
	if !ok {
		t.Fatalf("parsePacket failed")
	}
	if parsed.src != src.Addr() || parsed.dst != dst.Addr() ||
		parsed.srcPort != src.Port() || parsed.dstPort != dst.Port() {
		t.Fatalf("parsed mismatch: %+v vs src=%v dst=%v", parsed, src, dst)
	}
	gotPayload := pkt[info.l4+8:]
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch")
	}
}
