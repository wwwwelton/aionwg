package main

import (
	"net/netip"
	"testing"
)

func TestLearnedCandidatesStartWithCurrentAndSkipDuplicates(t *testing.T) {
	cur := netip.MustParseAddrPort("203.0.113.1:2408")
	if c := learnedCandidates(cur, nil); len(c) != 1 || c[0] != cur.Addr() {
		t.Fatalf("nothing learned: %v", c)
	}
	// the profile's own endpoint learned back (after a revert) is not an alternative
	if c := learnedCandidates(cur, []netip.AddrPort{cur}); len(c) != 1 {
		t.Fatalf("own endpoint is not an alternative: %v", c)
	}
	learned := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:2408"),
		netip.MustParseAddrPort("198.51.100.7:2409"),  // same address again
		netip.MustParseAddrPort("[2001:db8::1]:2408"), // IPv6 is not probed
		cur,
	}
	c := learnedCandidates(cur, learned)
	if len(c) != 2 || c[0] != cur.Addr() || c[1].String() != "198.51.100.7" {
		t.Fatalf("candidates: %v", c)
	}
}

func TestWithLearnedPortRestoresThePortItWasLearnedWith(t *testing.T) {
	learned := []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:4500")}
	ranked := netip.MustParseAddrPort("198.51.100.7:2408") // the ranking used the profile's port
	if got := withLearnedPort(ranked, learned); got.String() != "198.51.100.7:4500" {
		t.Fatalf("port not restored: %v", got)
	}
	other := netip.MustParseAddrPort("198.51.100.9:2408")
	if got := withLearnedPort(other, learned); got != other {
		t.Fatalf("an unknown address must keep its port: %v", got)
	}
}
