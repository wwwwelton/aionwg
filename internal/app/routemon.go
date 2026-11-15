package app

// Live route monitor (engine side in tunnel_windows.go). While the tunnel runs
// it keeps measuring the direct leg to every endpoint already proven to
// complete a handshake. When one is clearly faster it switches to it, then
// compares the real game ping before and after and goes back unless the game
// ping improved. Attempts are spaced out (a switch costs one handshake and the
// provider can rate-limit handshakes): there is no scan and no handshake burst.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	discoverEvery = 10 * time.Second // new endpoints are searched this often, only while the game is idle; each candidate is handshake-probed once
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

var routesMu sync.Mutex // serialises read-modify-write across engine goroutines

// mutateRoutes applies f to the routes file (missing or corrupt = empty) and
// writes it back atomically when f reports a change.
func mutateRoutes(path string, f func(m map[string][]string) bool) error {
	routesMu.Lock()
	defer routesMu.Unlock()
	var m map[string][]string
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if m == nil {
		m = map[string][]string{}
	}
	if !f(m) {
		return nil
	}
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

// saveRoute remembers ep for profile (no duplicates) without touching any
// WireGuard profile.
func saveRoute(path, profile string, ep netip.AddrPort) error {
	return mutateRoutes(path, func(m map[string][]string) bool {
		for _, s := range m[profile] {
			if s == ep.String() {
				return false
			}
		}
		m[profile] = append(m[profile], ep.String())
		return true
	})
}

// badTTL is how long an endpoint that failed a handshake is not tried again.
const badTTL = 7 * 24 * time.Hour

func badKey(profile string) string { return profile + "|bad" }

// parseBad reads a "ip@unixSeconds" entry.
func parseBad(s string) (netip.Addr, time.Time, bool) {
	a, ts, ok := strings.Cut(s, "@")
	if !ok {
		return netip.Addr{}, time.Time{}, false
	}
	addr, err := netip.ParseAddr(a)
	sec, err2 := strconv.ParseInt(ts, 10, 64)
	if err != nil || err2 != nil {
		return netip.Addr{}, time.Time{}, false
	}
	return addr, time.Unix(sec, 0), true
}

// saveBad remembers that ep did not complete a handshake so later connections
// skip it for badTTL (repeated failed handshakes can get a key rate-limited).
func saveBad(path, profile string, ep netip.AddrPort, now time.Time) error {
	return mutateRoutes(path, func(m map[string][]string) bool {
		var keep []string
		for _, s := range m[badKey(profile)] {
			if a, at, ok := parseBad(s); ok && a != ep.Addr() && now.Sub(at) < badTTL {
				keep = append(keep, s)
			}
		}
		m[badKey(profile)] = append(keep, fmt.Sprintf("%s@%d", ep.Addr(), now.Unix()))
		return true
	})
}

// loadBad returns the addresses that failed a handshake for profile less than
// badTTL ago; a missing or corrupt file yields none.
func loadBad(path, profile string, now time.Time) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	var m map[string][]string
	if b, err := os.ReadFile(path); err != nil || json.Unmarshal(b, &m) != nil {
		return out
	}
	for _, s := range m[badKey(profile)] {
		if a, at, ok := parseBad(s); ok && now.Sub(at) < badTTL {
			out[a] = true
		}
	}
	return out
}
