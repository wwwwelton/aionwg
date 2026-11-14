package main

// Live route monitor (engine side in tunnel_windows.go). While the tunnel runs
// it keeps measuring the direct leg to every endpoint already proven to
// complete a handshake. When one is clearly faster it switches to it, then
// compares the real game ping before and after and goes back unless the game
// ping improved. Attempts are spaced out (a switch costs one handshake and the
// provider can rate-limit handshakes): there is no scan and no handshake burst.

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	routeMargin = 5 * time.Millisecond // direct-leg gain that justifies a trial
	gameGain    = 2 * time.Millisecond // game-ping gain needed to keep a switch
	minPingRTTs = 5                    // samples needed for a median
)

// Timing is a variable only so tests can shrink it.
var (
	routeEvery    = 30 * time.Second
	routeSettle   = 12 * time.Second // game pings collected through the new path
	routeCooldown = 3 * time.Minute  // after a kept switch
	failCooldown  = 10 * time.Minute // after a failed or reverted one
)

// pickRoute returns the endpoint whose direct leg beats curLeg by routeMargin,
// the fastest one when several do.
func pickRoute(curLeg time.Duration, legs map[netip.AddrPort]time.Duration) (netip.AddrPort, bool) {
	var best netip.AddrPort
	bestLeg := curLeg - routeMargin // must be strictly below to count as a gain of routeMargin
	found := false
	for ep, leg := range legs {
		if leg <= bestLeg && (!found || leg < legs[best] || (leg == legs[best] && ep.String() < best.String())) {
			best, bestLeg, found = ep, leg, true
		}
	}
	return best, found
}

// keepRoute keeps a switch only when both measurements exist and the game ping
// improved by gameGain; an unknown measurement counts as "not proven better".
func keepRoute(before, after time.Duration) bool {
	return before > 0 && after > 0 && before-after >= gameGain
}

// medianRTT is the median of s, or 0 with fewer than minPingRTTs samples.
func medianRTT(s []time.Duration) time.Duration {
	if len(s) < minPingRTTs {
		return 0
	}
	c := append([]time.Duration(nil), s...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

func routesPath() string { return filepath.Join(appDir(), "routes.json") }

// loadRoutes returns the endpoints proven for profile; a missing or corrupt
// file yields none.
func loadRoutes(path, profile string) []netip.AddrPort {
	var m map[string][]string
	if b, err := os.ReadFile(path); err != nil || json.Unmarshal(b, &m) != nil {
		return nil
	}
	var out []netip.AddrPort
	for _, s := range m[profile] {
		if ep, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ep)
		}
	}
	return out
}

// saveRoute remembers ep for profile (no duplicates) without touching any
// WireGuard profile.
func saveRoute(path, profile string, ep netip.AddrPort) error {
	var m map[string][]string
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m == nil {
		m = map[string][]string{}
	}
	for _, s := range m[profile] {
		if s == ep.String() {
			return nil
		}
	}
	m[profile] = append(m[profile], ep.String())
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".routes-*.tmp")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		if werr != nil {
			return werr
		}
		return cerr
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
