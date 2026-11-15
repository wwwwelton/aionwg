//go:build windows

package app

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	cwbStartWait = 20 * time.Second // let the tunnel settle before the first round
	cwbEvery     = 10 * time.Minute // period between rounds
	cwbMaxTry    = 6                // endpoints measured per round
	cwbSampleFor = 15 * time.Second // deadline for the dummy-target samples of one endpoint
)

// cwbDummyTarget is measured through the tunnel on every endpoint, so the
// search works without the game running.
var cwbDummyTarget = geoResolver

type cwbResult struct {
	ep   netip.AddrPort
	colo string
	rtt  time.Duration
}

// cwbCandidates returns the current endpoint first, then the other endpoints
// already proven by a handshake, sorted, at most n in total.
func cwbCandidates(learned []netip.AddrPort, orig netip.AddrPort, n int) []netip.AddrPort {
	rest := make([]netip.AddrPort, 0, len(learned))
	for _, ep := range learned {
		if ep != orig {
			rest = append(rest, ep)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].String() < rest[j].String() })
	out := append([]netip.AddrPort{orig}, rest...)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// isCWB reports whether an id.server answer names a Curitiba colo (cwb02, ...).
func isCWB(colo string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(colo)), "cwb")
}

// cwbBest returns the cwb* result with the lowest RTT.
func cwbBest(res []cwbResult) (cwbResult, bool) {
	var best cwbResult
	ok := false
	for _, r := range res {
		if !isCWB(r.colo) || r.rtt <= 0 {
			continue
		}
		if !ok || r.rtt < best.rtt {
			best, ok = r, true
		}
	}
	return best, ok
}

// dummyRTT waits for the dummy-target samples on the current endpoint and returns their median.
func (e *Engine) dummyRTT() (time.Duration, bool) {
	e.pingMu.Lock()
	e.pings[pingIDDummy] = &pingState{target: cwbDummyTarget}
	e.pingMu.Unlock()
	for end := time.Now().Add(cwbSampleFor); time.Now().Before(end); {
		if !e.nap(500 * time.Millisecond) {
			return 0, false
		}
		e.pingMu.Lock()
		d := medianRTT(e.pings[pingIDDummy].rtts)
		e.pingMu.Unlock()
		if d > 0 {
			return d, true
		}
	}
	return 0, false
}

// cwbRound measures the handshake-proven endpoints one by one and leaves the
// tunnel on the lowest-RTT cwb* endpoint. With none found, the original stays.
func (e *Engine) cwbRound() {
	orig := e.eps()[0]
	var res []cwbResult
	for _, ep := range cwbCandidates(e.learnedList(), orig, cwbMaxTry) {
		if e.closing.Load() {
			return
		}
		if ep != orig && e.rejectByProbe(ep) {
			continue
		}
		if ep != orig {
			if err := e.SetEndpoint(ep); err != nil {
				e.routeLog("cwb: %s não trocou: %v", ep, err)
				continue
			}
		}
		e.refreshExit()
		x := e.exit.Load()
		if x == nil || x.Endpoint != ep || !isCWB(x.Colo) {
			continue
		}
		rtt, ok := e.dummyRTT()
		if !ok {
			e.routeLog("cwb: %s (%s) sem amostra do alvo dummy", ep, x.Colo)
			continue
		}
		res = append(res, cwbResult{ep: ep, colo: x.Colo, rtt: rtt})
		noteEndpointRTT(ep, rtt)
		e.routeLog("cwb: %s · %s · %v", ep, x.Colo, rtt)
	}
	best, ok := cwbBest(res)
	if !ok {
		e.routeLog("cwb: nenhum endpoint cwb* entre os já validados; mantendo %s", orig)
		best = cwbResult{ep: orig}
	}
	if err := e.SetEndpoint(best.ep); err != nil {
		e.routeLog("cwb: não foi possível voltar para %s: %v", best.ep, err)
		return
	}
	if ok {
		e.routeLog("cwb: escolhido %s · %s · %v", best.ep, best.colo, best.rtt)
	}
}

// cwbLoop runs a round at startup and then every cwbEvery.
func (e *Engine) cwbLoop() {
	if !e.nap(cwbStartWait) {
		return
	}
	for {
		e.cwbRound()
		if !e.nap(cwbEvery) {
			return
		}
	}
}
