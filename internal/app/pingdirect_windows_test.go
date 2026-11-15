//go:build windows

package app

import (
	"net/netip"
	"testing"
	"time"
)

// The direct probe must reach the game server straight over Windows ICMP and
// fill Stats; a loopback "game server" answers without any network.
func TestPingLoopMeasuresTheGameServerDirectly(t *testing.T) {
	game := netip.MustParseAddr("127.0.0.1")
	e := &Engine{
		stop:    make(chan struct{}),
		addr4:   netip.MustParseAddr("10.9.0.2"),
		tun:     newSplitTun(1420),
		pings:   map[uint16]*pingState{0: {}, pingIDGateway: {}, pingIDGame: {}, pingIDGameDirect: {}},
		pending: map[uint32]time.Time{},
		nat:     map[portKey]*natEntry{{protoTCP, 1}: {remote: game, game: true, last: time.Now().Add(time.Hour)}},
		logf:    t.Logf,
	}
	e.epCur.Store(&[]netip.AddrPort{netip.MustParseAddrPort("127.0.0.2:51820")})
	go e.pingLoop()
	defer close(e.stop)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		e.pingMu.Lock()
		ps := e.pings[pingIDGameDirect]
		ok, target := ps.ok, ps.target
		e.pingMu.Unlock()
		if ok {
			if target != game {
				t.Fatalf("probe target %v, want %v", target, game)
			}
			r := PingResult{OK: true}
			e.pingMu.Lock()
			r.RTT = e.pings[pingIDGameDirect].last
			e.pingMu.Unlock()
			if pingMs(PingResult{OK: true, RTT: r.RTT}) < 1 {
				t.Fatalf("pingMs must round a sub-millisecond reply up to 1")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no direct reply from the game server within 6 s")
}
