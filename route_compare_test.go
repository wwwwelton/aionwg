package main

import (
	"testing"
	"time"
)

func TestRouteComparatorPrefersStablePath(t *testing.T) {
	candidates := []RouteCandidate{
		{Kind: RouteDirect, Measurement: RouteMeasurement{Available: true, RTT: 20 * time.Millisecond, P95: 30 * time.Millisecond, Jitter: 8 * time.Millisecond}},
		{Kind: RouteWireGuard, Measurement: RouteMeasurement{Available: true, RTT: 22 * time.Millisecond, P95: 24 * time.Millisecond, Jitter: 1 * time.Millisecond}},
	}
	ranked := rankRouteCandidates(candidates)
	if ranked[0].Kind != RouteWireGuard {
		t.Fatalf("best route = %s, want %s", ranked[0].Kind, RouteWireGuard)
	}
}

func TestRouteComparatorHonorsCooldownAndLock(t *testing.T) {
	now := time.Unix(100, 0)
	candidates := []RouteCandidate{
		{Kind: RouteDirect, Measurement: RouteMeasurement{Available: true, RTT: 40 * time.Millisecond}},
		{Kind: RouteRelay, Measurement: RouteMeasurement{Available: true, RTT: 10 * time.Millisecond}},
	}
	if _, changed := chooseRoute(candidates, RouteDirect, now, now.Add(-time.Second), time.Minute, 1); changed {
		t.Fatal("route changed during cooldown")
	}
	candidates[1].Locked = true
	if _, changed := chooseRoute(candidates, RouteDirect, now, time.Time{}, 0, 1); changed {
		t.Fatal("locked route was selected")
	}
}
