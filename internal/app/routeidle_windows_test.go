//go:build windows

package app

import (
	"strings"
	"testing"
	"time"
)

// With no game traffic the scan loop searches for new endpoints, never switches the
// live one, and stops cleanly. A loopback endpoint has no neighbours, so the
// search ends at once and leaves the route alone.
func TestRouteLoopIdleSearchNeverTouchesTheLiveRoute(t *testing.T) {
	e, a, _, logs := routeFixture(t)
	e.nat = map[portKey]*natEntry{} // the game is not running
	e.tun = newSplitTun(1420)       // scanLoop asks for the exit location through it
	defer func(ev, di time.Duration) { routeEvery, discoverEvery = ev, di }(routeEvery, discoverEvery)
	routeEvery, discoverEvery = 30*time.Millisecond, 10*time.Millisecond
	done := make(chan struct{})
	go func() { e.scanLoop(true); close(done) }()
	time.Sleep(400 * time.Millisecond)
	close(e.stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("scanLoop did not stop")
	}
	if got := e.eps()[0]; got != a {
		t.Fatalf("idle search must not switch the endpoint: %v", got)
	}
	if strings.Contains(logs(), "testando") {
		t.Fatalf("no game ping trial without game traffic:\n%s", logs())
	}
}
