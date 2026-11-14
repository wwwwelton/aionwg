//go:build windows

package main

import (
	"strings"
	"testing"
	"time"
)

// With no game traffic the loop searches for new endpoints, never switches the
// live one, and stops cleanly. A loopback endpoint has no neighbours, so the
// search ends at once and leaves the route alone.
func TestRouteLoopIdleSearchNeverTouchesTheLiveRoute(t *testing.T) {
	e, a, _, logs := routeFixture(t)
	e.nat = map[portKey]*natEntry{} // the game is not running
	defer func(ev, di time.Duration) { routeEvery, discoverEvery = ev, di }(routeEvery, discoverEvery)
	routeEvery, discoverEvery = 30*time.Millisecond, 10*time.Millisecond
	done := make(chan struct{})
	go func() { e.routeLoop(); close(done) }()
	time.Sleep(400 * time.Millisecond)
	close(e.stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("routeLoop did not stop")
	}
	if got := e.eps()[0]; got != a {
		t.Fatalf("idle search must not switch the endpoint: %v", got)
	}
	if strings.Contains(logs(), "testando") {
		t.Fatalf("no game ping trial without game traffic:\n%s", logs())
	}
}
