//go:build windows

package app

import (
	"net/netip"
	"testing"
)

// The exit query leaves through the tunnel and the answer, delivered by the
// inbound path, reaches the waiting caller.
func TestGeoAskGetsTheAnswerThroughTheTunnel(t *testing.T) {
	e := &Engine{tun: newSplitTun(1420), addr4: netip.MustParseAddr("172.16.0.2"), stop: make(chan struct{})}
	go func() {
		pkt := <-e.tun.in
		p, _ := parsePacket(pkt)
		q := pkt[p.l4+8 : pktLen(pkt, &p)]
		reply := buildUDP4(geoResolver, e.addr4, 53, geoPort, chaosReply(q, "cwb01"))
		rp, _ := parsePacket(reply)
		e.geoReply(reply, &rp)
	}()
	got, ok := e.geoAsk("id.server")
	if !ok || got != "cwb01" {
		t.Fatalf("got %q %v", got, ok)
	}
}

func TestWGStatsLoopStopsWithEngine(t *testing.T) {
	e := &Engine{stop: make(chan struct{})}
	e.wg.Add(1)
	go e.wgStatsLoop()
	close(e.stop)
	e.wg.Wait()
}
