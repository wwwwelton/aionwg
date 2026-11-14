package main

// Multipath: besides the primary tunnel the engine can run extra WireGuard
// devices (same key and tunnel address), each through a different endpoint.
// The pure parts live here: which endpoints may be used and how a path's
// health is read. The engine side is paths_windows.go.

import (
	"net/netip"
	"time"
)

const (
	maxPaths       = 4
	pathAliveFor   = 75 * time.Second
	pathStagger    = 10 * time.Second // one new path at a time
	pathRetryAfter = 5 * time.Minute
)

// warpAltPorts are the fallback WireGuard ports Cloudflare documents.
var warpAltPorts = []uint16{500, 1701, 4500}

// pathPool lists learned endpoints and known WARP endpoint candidates.
// Other VPNs do not receive guessed neighbours.
func pathPool(cur netip.AddrPort, learned []netip.AddrPort) []netip.AddrPort {
	var out []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	add := func(ep netip.AddrPort) {
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	for _, l := range learned {
		add(l)
	}
	seeds := warpPathSeeds(cur.Addr())
	if len(seeds) == 0 {
		return out
	}
	ips := append([]netip.Addr{cur.Addr()}, seeds...)
	for _, a := range seeds {
		add(netip.AddrPortFrom(a, cur.Port()))
	}
	for _, port := range warpAltPorts {
		for _, a := range ips {
			add(netip.AddrPortFrom(a, port))
		}
	}
	return out
}

func warpPathSeeds(cur netip.Addr) []netip.Addr {
	if cur.Is4() {
		seeds := warpSeeds(cur)
		out := seeds[:0]
		for _, a := range seeds {
			b := a.As4()
			if b[0] != 162 || b[2] == 192 || b[2] == 195 {
				out = append(out, a)
			}
		}
		return out
	}
	if !netip.MustParsePrefix("2606:4700:d0::/64").Contains(cur) &&
		!netip.MustParsePrefix("2606:4700:d1::/64").Contains(cur) &&
		!netip.MustParsePrefix("2606:4700:100::/48").Contains(cur) {
		return nil
	}
	var out []netip.Addr
	for _, s := range []string{
		"2606:4700:d0::a29f:c001", "2606:4700:d1::a29f:c001",
		"2606:4700:d0::a29f:c301", "2606:4700:d1::a29f:c301",
		"2606:4700:d0::bc72:6001", "2606:4700:d1::bc72:6001",
	} {
		if a := netip.MustParseAddr(s); a != cur {
			out = append(out, a)
		}
	}
	return out
}

// pickPathEndpoint returns the first pool entry on an address no path uses
// yet; failing that, one on an unused address:port. Addresses in bad are
// never returned.
func pickPathEndpoint(pool, used []netip.AddrPort, bad map[netip.Addr]bool) (netip.AddrPort, bool) {
	usedAddr := map[netip.Addr]bool{}
	usedEP := map[netip.AddrPort]bool{}
	for _, u := range used {
		usedAddr[u.Addr()] = true
		usedEP[u] = true
	}
	for _, ep := range pool {
		if !bad[ep.Addr()] && !usedAddr[ep.Addr()] {
			return ep, true
		}
	}
	for _, ep := range pool {
		if !bad[ep.Addr()] && !usedEP[ep] {
			return ep, true
		}
	}
	return netip.AddrPort{}, false
}
