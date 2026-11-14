package main

import (
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestPathPoolNeverGuessesNeighboursOfOtherNetworks(t *testing.T) {
	if p := pathPool(ap("203.0.113.1:51820"), nil); len(p) != 0 {
		t.Fatalf("non-WARP endpoint got a pool: %v", p)
	}
	learned := []netip.AddrPort{ap("203.0.113.9:51820")}
	if p := pathPool(ap("203.0.113.1:51820"), learned); len(p) != 1 || p[0] != learned[0] {
		t.Fatalf("only learned endpoints expected: %v", p)
	}
}

func TestPathPoolForWarpHasSeedsThenFallbackPorts(t *testing.T) {
	p := pathPool(ap("162.159.192.1:2408"), nil)
	if len(p) == 0 || p[0].Port() != 2408 {
		t.Fatalf("pool = %v", p)
	}
	for _, ep := range p {
		if ep == ap("162.159.192.1:2408") {
			t.Fatal("the current endpoint is not a candidate")
		}
	}
	seen := map[netip.AddrPort]bool{}
	for _, ep := range p {
		if seen[ep] {
			t.Fatalf("duplicate %v", ep)
		}
		seen[ep] = true
	}
	if !seen[ap("162.159.192.1:500")] || !seen[ap("188.114.96.1:4500")] {
		t.Fatal("fallback ports missing")
	}
}

func TestPickPathEndpointPrefersUnusedAddressesAndSkipsBad(t *testing.T) {
	pool := []netip.AddrPort{ap("1.1.1.1:2408"), ap("2.2.2.2:2408"), ap("3.3.3.3:2408"), ap("1.1.1.1:500")}
	used := []netip.AddrPort{ap("1.1.1.1:2408")}
	bad := map[netip.Addr]bool{netip.MustParseAddr("2.2.2.2"): true}
	if got, ok := pickPathEndpoint(pool, used, bad); !ok || got != ap("3.3.3.3:2408") {
		t.Fatalf("got %v %v", got, ok)
	}
	used = append(used, ap("3.3.3.3:2408"))
	if got, ok := pickPathEndpoint(pool, used, bad); !ok || got != ap("1.1.1.1:500") {
		t.Fatalf("with every address taken, another port of one is fine: %v %v", got, ok)
	}
	used = append(used, ap("1.1.1.1:500"))
	if _, ok := pickPathEndpoint(pool, used, bad); ok {
		t.Fatal("nothing should be left")
	}
}

func TestPathPoolSupportsIPv6WarpEndpoints(t *testing.T) {
	cur := ap("[2606:4700:d0::a29f:c001]:2408")
	pool := pathPool(cur, nil)
	if len(pool) < 3 {
		t.Fatalf("not enough IPv6 endpoints: %v", pool)
	}
	for _, ep := range pool {
		if ep == cur || !ep.Addr().Is6() {
			t.Fatalf("invalid IPv6 candidate: %v", ep)
		}
	}
}
