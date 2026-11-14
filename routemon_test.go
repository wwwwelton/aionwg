package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPickRouteNeedsTheMarginAndPicksTheFastest(t *testing.T) {
	ms := time.Millisecond
	a := netip.MustParseAddrPort("198.51.100.1:2408")
	b := netip.MustParseAddrPort("198.51.100.2:2408")
	if _, ok := pickRoute(20*ms, map[netip.AddrPort]time.Duration{a: 16 * ms}); ok {
		t.Fatal("a 4 ms gain is below the margin")
	}
	if ep, ok := pickRoute(20*ms, map[netip.AddrPort]time.Duration{a: 15 * ms}); !ok || ep != a {
		t.Fatalf("a 5 ms gain must count: %v %v", ep, ok)
	}
	if ep, ok := pickRoute(30*ms, map[netip.AddrPort]time.Duration{a: 20 * ms, b: 12 * ms}); !ok || ep != b {
		t.Fatalf("fastest must win: %v %v", ep, ok)
	}
	if _, ok := pickRoute(30*ms, nil); ok {
		t.Fatal("no candidates")
	}
}

func TestKeepRouteOnlyWhenGamePingProvablyImproved(t *testing.T) {
	ms := time.Millisecond
	for _, tc := range []struct {
		before, after time.Duration
		want          bool
	}{
		{30 * ms, 27 * ms, true}, {30 * ms, 28 * ms, true}, {30 * ms, 29 * ms, false},
		{30 * ms, 40 * ms, false}, {0, 20 * ms, false}, {30 * ms, 0, false},
	} {
		if got := keepRoute(tc.before, tc.after); got != tc.want {
			t.Errorf("keepRoute(%v,%v)=%v want %v", tc.before, tc.after, got, tc.want)
		}
	}
}

func TestMedianRTTNeedsEnoughSamples(t *testing.T) {
	ms := time.Millisecond
	if medianRTT([]time.Duration{ms, ms, ms, ms}) != 0 {
		t.Fatal("4 samples are not enough")
	}
	if got := medianRTT([]time.Duration{9 * ms, 1 * ms, 5 * ms, 7 * ms, 3 * ms}); got != 5*ms {
		t.Fatalf("median %v", got)
	}
}

func TestRoutesPersistPerProfileWithoutDuplicatesAndSurviveCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "routes.json")
	a := netip.MustParseAddrPort("198.51.100.1:2408")
	b := netip.MustParseAddrPort("198.51.100.2:2408")
	for _, step := range []struct {
		profile string
		ep      netip.AddrPort
	}{{"p1.conf", a}, {"p1.conf", a}, {"p1.conf", b}, {"p2.conf", b}} {
		if err := saveRoute(path, step.profile, step.ep); err != nil {
			t.Fatal(err)
		}
	}
	if got := loadRoutes(path, "p1.conf"); len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("p1: %v", got)
	}
	if got := loadRoutes(path, "p2.conf"); len(got) != 1 || got[0] != b {
		t.Fatalf("p2: %v", got)
	}
	if got := loadRoutes(path, "other.conf"); len(got) != 0 {
		t.Fatalf("unknown profile: %v", got)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadRoutes(path, "p1.conf"); len(got) != 0 {
		t.Fatalf("corrupt file must yield nothing: %v", got)
	}
	if err := saveRoute(path, "p1.conf", a); err != nil {
		t.Fatalf("a corrupt file must be replaced, not fatal: %v", err)
	}
	if got := loadRoutes(path, "p1.conf"); len(got) != 1 || got[0] != a {
		t.Fatalf("after recovery: %v", got)
	}
}
