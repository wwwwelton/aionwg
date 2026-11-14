package main

import (
	"testing"
	"time"
)

// udpReply builds a minimal IPv4/UDP packet and its parsed info for the filter.
func udpReply(t *testing.T, srcPort, dstPort uint16, payload string) ([]byte, pktInfo) {
	t.Helper()
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
	pkt[9] = protoUDP
	pkt[20], pkt[21] = byte(srcPort>>8), byte(srcPort)
	pkt[22], pkt[23] = byte(dstPort>>8), byte(dstPort)
	copy(pkt[28:], payload)
	p := pktInfo{proto: protoUDP, l4: 20, srcPort: srcPort, dstPort: dstPort}
	return pkt, p
}

func TestMeterDedupDropsIdenticalReplyWithinWindow(t *testing.T) {
	var d meterDedup
	now := time.Unix(100, 0)
	pkt, p := udpReply(t, 7000, 5000, "reply")
	if d.seen(pkt, &p, now) {
		t.Fatal("first reply must reach the meter")
	}
	if !d.seen(pkt, &p, now.Add(20*time.Millisecond)) {
		t.Fatal("identical reply inside the window must be hidden from the meter")
	}
	if got := d.droppedCount(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestMeterDedupKeepsReplyAfterWindowAndDifferentPayload(t *testing.T) {
	var d meterDedup
	now := time.Unix(100, 0)
	a, pa := udpReply(t, 7000, 5000, "reply")
	b, pb := udpReply(t, 7000, 5000, "other")
	d.seen(a, &pa, now)
	if d.seen(b, &pb, now.Add(time.Millisecond)) {
		t.Fatal("different payload must reach the meter")
	}
	if d.seen(a, &pa, now.Add(meterDupWindow+time.Millisecond)) {
		t.Fatal("same reply after the window is a new reply and must reach the meter")
	}
}

func TestMeterDedupEmptyPayloadNeverDropped(t *testing.T) {
	var d meterDedup
	now := time.Unix(100, 0)
	pkt, p := udpReply(t, 7000, 5000, "")
	d.seen(pkt, &p, now)
	if d.seen(pkt, &p, now) {
		t.Fatal("empty UDP payload must always reach the meter")
	}
}
