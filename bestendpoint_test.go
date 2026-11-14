package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func probeTable(m map[string]time.Duration) func(netip.Addr) (time.Duration, bool) {
	return func(a netip.Addr) (time.Duration, bool) {
		d, ok := m[a.String()]
		return d, ok
	}
}

func TestBestEndpointPicksClearlyFasterKeepsPortAndFallsBack(t *testing.T) {
	cur := netip.MustParseAddrPort("203.0.113.1:2408")
	cands := endpointCandidates(cur, "vpn.example.net", []string{"198.51.100.1", "198.51.100.2"}, func(string) ([]netip.Addr, error) { return nil, errors.New("no dns") })
	ms := time.Millisecond
	for name, tc := range map[string]struct {
		rtt  map[string]time.Duration
		want string
	}{
		"faster wins":          {map[string]time.Duration{"203.0.113.1": 25 * ms, "198.51.100.1": 14 * ms, "198.51.100.2": 13 * ms}, "198.51.100.2:2408"},
		"within margin stays":  {map[string]time.Duration{"203.0.113.1": 15 * ms, "198.51.100.2": 13 * ms}, "203.0.113.1:2408"},
		"silent current stays": {map[string]time.Duration{"198.51.100.2": 5 * ms}, "203.0.113.1:2408"},
		"nobody answers stays": {map[string]time.Duration{}, "203.0.113.1:2408"},
	} {
		got, _, _ := bestEndpoint(cur, cands, probeTable(tc.rtt))
		if got.String() != tc.want {
			t.Errorf("%s: got %s want %s", name, got, tc.want)
		}
	}
}

func TestEndpointCandidatesSources(t *testing.T) {
	cur := netip.MustParseAddrPort("203.0.113.10:51820")
	one := func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil }
	if c := endpointCandidates(cur, "vpn.example.net", nil, one); len(c) != 1 {
		t.Fatalf("single-IP VPS must have no alternative: %v", c)
	}
	multi := func(h string) ([]netip.Addr, error) {
		if h == "alt.example.net" {
			return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::1")}, nil
	}
	c := endpointCandidates(cur, "vpn.example.net", []string{"alt.example.net", " 198.51.100.7 ", ""}, multi)
	if len(c) != 3 || c[0] != cur.Addr() || c[1].String() != "198.51.100.7" || c[2].String() != "192.0.2.9" {
		t.Fatalf("current first, then distinct IPv4 from DNS and extras: %v", c)
	}
	lit := func(string) ([]netip.Addr, error) { t.Fatal("literal IP must not be resolved"); return nil, nil }
	if c := endpointCandidates(cur, "203.0.113.10", nil, lit); len(c) != 1 {
		t.Fatalf("literal IP: %v", c)
	}
}

func TestHandshakenPeersOnlyListsPeersWithAHandshake(t *testing.T) {
	dump := "private_key=x\nlisten_port=1\npublic_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" +
		"public_key=bb\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n"
	got := handshakenPeers(dump)
	if got["aa"] || !got["bb"] || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
