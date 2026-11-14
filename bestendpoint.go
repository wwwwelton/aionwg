package main

// Optional route optimisation: at connect time pick the lowest-latency IPv4
// endpoint among the profile's own one, every address its host name resolves
// to (multi-record VPS names) and the user's endpoint_candidates (settings).
// The engine then confirms a WireGuard handshake and falls back to the
// profile's endpoint otherwise (ICMP can answer where WireGuard does not).
// Nothing changes when the current endpoint is already the fastest, does not
// answer ICMP, or has no alternative. No addresses are built into the program.

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// endpointMargin keeps the current endpoint unless another is clearly faster
// (ICMP has 1 ms resolution on Windows).
const endpointMargin = 3 * time.Millisecond

func lookupIPv4(host string) ([]netip.Addr, error) {
	ips, err := net.LookupIP(host)
	var out []netip.Addr
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			if a, ok := netip.AddrFromSlice(v4); ok {
				out = append(out, a)
			}
		}
	}
	return out, err
}

// endpointCandidates returns cur first, then the distinct IPv4 alternatives
// from the endpoint's host name and from extra (IPs or host names).
func endpointCandidates(cur netip.AddrPort, host string, extra []string, lookup func(string) ([]netip.Addr, error)) []netip.Addr {
	cands := []netip.Addr{cur.Addr()}
	seen := map[netip.Addr]bool{cur.Addr(): true}
	add := func(a netip.Addr) {
		if a.Is4() && !seen[a] {
			seen[a] = true
			cands = append(cands, a)
		}
	}
	for _, h := range append([]string{host}, extra...) {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil {
			add(a)
			continue
		}
		ips, _ := lookup(h)
		for _, a := range ips {
			add(a)
		}
	}
	return cands
}

// bestEndpoint probes cands (cands[0] is the current endpoint) concurrently
// and returns the endpoint to use with the measured latencies (0 = unknown).
func bestEndpoint(cur netip.AddrPort, cands []netip.Addr, probe func(netip.Addr) (time.Duration, bool)) (best netip.AddrPort, curRTT, bestRTT time.Duration) {
	rtts := make([]time.Duration, len(cands))
	oks := make([]bool, len(cands))
	var wg sync.WaitGroup
	for i, a := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rtts[i], oks[i] = probe(a)
		}()
	}
	wg.Wait()
	if !oks[0] {
		return cur, 0, 0 // cannot compare against a silent current endpoint
	}
	bi := 0
	for i := 1; i < len(cands); i++ {
		if oks[i] && rtts[i] < rtts[bi] {
			bi = i
		}
	}
	if rtts[0]-rtts[bi] < endpointMargin {
		return cur, rtts[0], rtts[0]
	}
	return netip.AddrPortFrom(cands[bi], cur.Port()), rtts[0], rtts[bi]
}

// handshakenPeers returns the hex public keys that have a handshake time in a
// UAPI dump.
func handshakenPeers(ipc string) map[string]bool {
	out := map[string]bool{}
	var pk string
	for _, l := range strings.Split(ipc, "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "public_key":
			pk = v
		case "last_handshake_time_sec":
			if v != "0" && pk != "" {
				out[pk] = true
			}
		}
	}
	return out
}
