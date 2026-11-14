package main

// Optional route optimisation, no addresses built in or configured. At connect
// time the candidates are derived from the profile's endpoint itself: every
// IPv4 its host name resolves to, plus (for a public endpoint) the addresses
// with the same host octet in the other /24 blocks of its /22. One ICMP echo
// ranks them all, medians confirm the best few, and a throwaway WireGuard
// handshake (engine side) decides which one is really a WireGuard server, since
// many neighbours answer ping but are unrelated hosts. Nothing changes when the
// current endpoint is already the fastest, does not answer ICMP, or nothing
// better completes a handshake.

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	endpointMargin = 3 * time.Millisecond // ICMP has 1 ms resolution on Windows
	sweepKeep      = 8                    // best sweep answers that get a 5-echo median
	maxTrials      = 2                    // handshakes tried, best first
	sweepWorkers   = 64
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

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

// endpointCandidates returns cur first, then the distinct IPv4 alternatives.
func endpointCandidates(cur netip.AddrPort, host string, lookup func(string) ([]netip.Addr, error)) []netip.Addr {
	cands := []netip.Addr{cur.Addr()}
	seen := map[netip.Addr]bool{cur.Addr(): true}
	add := func(a netip.Addr) {
		if a.Is4() && !seen[a] {
			seen[a] = true
			cands = append(cands, a)
		}
	}
	if _, err := netip.ParseAddr(host); err != nil { // a name, not a literal IP
		ips, _ := lookup(host)
		for _, a := range ips {
			add(a)
		}
	}
	if a := cur.Addr(); a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a) {
		b := a.As4()
		base := int(b[2] &^ 3) // the endpoint's /22: good neighbours sit in consecutive /24 blocks
		for n := base; n < base+4; n++ {
			b[2] = byte(n)
			add(netip.AddrFrom4(b))
		}
	}
	return cands
}

// learnedCandidates returns cur first, then the distinct IPv4 addresses of the
// endpoints already proven for the profile. A single result means nothing
// useful is known yet.
func learnedCandidates(cur netip.AddrPort, learned []netip.AddrPort) []netip.Addr {
	cands := []netip.Addr{cur.Addr()}
	seen := map[netip.Addr]bool{cur.Addr(): true}
	for _, l := range learned {
		if a := l.Addr(); a.Is4() && !seen[a] {
			seen[a] = true
			cands = append(cands, a)
		}
	}
	return cands
}

// withLearnedPort gives a ranked address the port it was learned with (the
// ranking only knows the profile's port).
func withLearnedPort(ep netip.AddrPort, learned []netip.AddrPort) netip.AddrPort {
	for _, l := range learned {
		if l.Addr() == ep.Addr() {
			return l
		}
	}
	return ep
}

type rankedEndpoint struct {
	netip.AddrPort
	RTT time.Duration
}

// rankEndpoints measures cands (cands[0] is the current endpoint) and returns
// the current latency (0 = it does not answer, so nothing is compared) and the
// alternatives at least endpointMargin faster, best first, at most maxTrials.
// sweep is one echo; median is the careful measurement. Both must be safe to
// call concurrently.
func rankEndpoints(cur netip.AddrPort, cands []netip.Addr, sweep, median func(netip.Addr) (time.Duration, bool)) (curRTT time.Duration, ranked []rankedEndpoint) {
	type answer struct {
		addr netip.Addr
		rtt  time.Duration
		ok   bool
	}
	run := func(addrs []netip.Addr, probe func(netip.Addr) (time.Duration, bool)) []answer {
		out := make([]answer, len(addrs))
		sem := make(chan struct{}, sweepWorkers)
		var wg sync.WaitGroup
		for i, a := range addrs {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				r, ok := probe(a)
				out[i] = answer{a, r, ok}
			}()
		}
		wg.Wait()
		return out
	}
	var alive []answer
	for _, r := range run(cands[1:], sweep) {
		if r.ok {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].rtt < alive[j].rtt })
	if len(alive) > sweepKeep {
		alive = alive[:sweepKeep]
	}
	probe := []netip.Addr{cur.Addr()}
	for _, r := range alive {
		probe = append(probe, r.addr)
	}
	meds := run(probe, median)
	if !meds[0].ok {
		return 0, nil
	}
	curRTT = meds[0].rtt
	for _, m := range meds[1:] {
		if m.ok && curRTT-m.rtt >= endpointMargin {
			ranked = append(ranked, rankedEndpoint{netip.AddrPortFrom(m.addr, cur.Port()), m.rtt})
		}
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].RTT < ranked[j].RTT })
	if len(ranked) > maxTrials {
		ranked = ranked[:maxTrials]
	}
	return curRTT, ranked
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

// dropAddrs removes the addresses in drop from cands, never the first one (the
// current endpoint).
func dropAddrs(cands []netip.Addr, drop map[netip.Addr]bool) []netip.Addr {
	out := cands[:1:1]
	for _, a := range cands[1:] {
		if !drop[a] {
			out = append(out, a)
		}
	}
	return out
}
