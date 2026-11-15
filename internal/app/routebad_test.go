package app

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFailedEndpointsAreSkippedForAWeekPerProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	now := time.Unix(1_800_000_000, 0)
	bad := netip.MustParseAddrPort("198.51.100.7:2408")
	if err := saveBad(path, "p1.conf", bad, now); err != nil {
		t.Fatal(err)
	}
	if !loadBad(path, "p1.conf", now.Add(time.Hour))[bad.Addr()] {
		t.Fatal("a fresh failure must be remembered")
	}
	if loadBad(path, "p2.conf", now.Add(time.Hour))[bad.Addr()] {
		t.Fatal("failures are per profile")
	}
	if loadBad(path, "p1.conf", now.Add(badTTL+time.Second))[bad.Addr()] {
		t.Fatal("a failure older than the TTL must be forgotten")
	}
	// remembering again refreshes the entry instead of duplicating it
	if err := saveBad(path, "p1.conf", bad, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := loadBad(path, "p1.conf", now.Add(badTTL+time.Hour)); !got[bad.Addr()] || len(got) != 1 {
		t.Fatalf("refreshed entry: %v", got)
	}
	// learned routes and failures share the file without disturbing each other
	good := netip.MustParseAddrPort("198.51.100.9:2408")
	if err := saveRoute(path, "p1.conf", good); err != nil {
		t.Fatal(err)
	}
	if got := loadRoutes(path, "p1.conf"); len(got) != 1 || got[0] != good {
		t.Fatalf("learned routes: %v", got)
	}
	if !loadBad(path, "p1.conf", now.Add(3*time.Hour))[bad.Addr()] {
		t.Fatal("saving a route must keep the failure list")
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadBad(path, "p1.conf", now); len(got) != 0 {
		t.Fatalf("corrupt file yields none: %v", got)
	}
}

func TestDropAddrsKeepsTheCurrentEndpointAndAliasesNothing(t *testing.T) {
	cur, a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.114.1"), netip.MustParseAddr("203.0.115.1")
	cands := []netip.Addr{cur, a, b}
	got := dropAddrs(cands, map[netip.Addr]bool{a: true, cur: true})
	if len(got) != 2 || got[0] != cur || got[1] != b {
		t.Fatalf("got %v", got)
	}
	if cands[1] != a || cands[2] != b {
		t.Fatalf("the input slice must not be modified: %v", cands)
	}
}

func TestNeighbourBlockStopsAtTheEdgesOfItsSlash22(t *testing.T) {
	noDNS := func(string) ([]netip.Addr, error) { return nil, nil }
	for _, tc := range []struct {
		ep       string
		lo, hi   byte
		wantSelf byte
	}{
		{"203.0.255.1:51820", 252, 255, 255},
		{"203.0.0.1:51820", 0, 3, 0},
		{"188.114.96.1:2408", 96, 99, 96},
	} {
		ep := netip.MustParseAddrPort(tc.ep)
		c := endpointCandidates(ep, "x", noDNS)
		if len(c) != 4 || c[0] != ep.Addr() {
			t.Fatalf("%s: %v", tc.ep, c)
		}
		for _, a := range c {
			if b := a.As4()[2]; b < tc.lo || b > tc.hi {
				t.Fatalf("%s: %v is outside the /22", tc.ep, a)
			}
		}
	}
}
