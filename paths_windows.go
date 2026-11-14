//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type udpPathStatus struct {
	Endpoint netip.AddrPort
	Active   bool
	RTT      time.Duration
	Age      time.Duration
}

// startUDPPaths leaves ordinary WireGuard profiles unchanged. WARP profiles
// receive three additional sessions, each on its own endpoint and UDP socket.
func (e *Engine) startUDPPaths() error {
	if len(e.conf.Peers) != 1 || len(warpPathSeeds(e.eps()[0].Addr())) == 0 {
		return nil
	}
	learned := e.learnedList()
	sort.Slice(learned, func(i, j int) bool { return learned[i].Compare(learned[j]) < 0 })
	pool := pathPool(e.eps()[0], learned)
	used := []netip.AddrPort{e.eps()[0]}
	for i := range e.paths {
		ep, ok := pickPathEndpoint(pool, used, nil)
		if !ok {
			return fmt.Errorf("não há quatro endpoints UDP distintos para o WARP")
		}
		p, err := newUDPPath(e.conf, ep, uint16(0xa110+i), e.handleInbound)
		if err != nil {
			return fmt.Errorf("criando caminho UDP %d para %s: %w", i+2, ep, err)
		}
		e.paths[i] = p
		used = append(used, ep)
		e.logf("UDP caminho %d/4: %s (aguardando resposta)", i+2, ep)
	}
	return nil
}

func (e *Engine) pathEndpointUsed(ep netip.AddrPort) bool {
	return e.pathIndexUsing(ep) >= 0
}

// pathIndexUsing returns the extra path index holding ep, or -1.
func (e *Engine) pathIndexUsing(ep netip.AddrPort) int {
	for i, p := range e.paths {
		if p != nil && p.currentEndpoint() == ep {
			return i
		}
	}
	return -1
}

// pathLoop probes one path per tick, avoiding simultaneous handshakes with the
// same account. A path that stops replying is rotated to another endpoint.
func (e *Engine) pathLoop() {
	ticker := time.NewTicker(pathStagger)
	defer ticker.Stop()
	bad := make(map[netip.Addr]bool)
	var misses [maxPaths - 1]int
	var lastReset time.Time
	var reported [maxPaths - 1]bool
	for i := 0; ; i = (i + 1) % len(e.paths) {
		select {
		case <-e.stop:
			return
		case <-ticker.C:
		}
		if e.closing.Load() {
			return
		}
		p := e.paths[i]
		if p == nil {
			continue
		}
		ready := p.active(time.Now())
		if ready != reported[i] {
			reported[i] = ready
			if ready {
				e.logf("UDP caminho %d: dados confirmados em %s (%s)", i+2, p.currentEndpoint(), time.Duration(p.rtt.Load()).Round(time.Millisecond))
			} else {
				e.logf("UDP caminho %d: sem resposta em %s", i+2, p.currentEndpoint())
			}
		}
		if ready {
			misses[i] = 0
		} else if misses[i] >= 3 {
			if lastReset.IsZero() || time.Since(lastReset) >= pathRetryAfter {
				clear(bad)
				lastReset = time.Now()
			}
			bad[p.currentEndpoint().Addr()] = true
			e.epMu.Lock()
			used := []netip.AddrPort{e.eps()[0]}
			for _, other := range e.paths {
				if other != nil {
					used = append(used, other.currentEndpoint())
				}
			}
			next, ok := pickPathEndpoint(pathPool(e.eps()[0], e.learnedList()), used, bad)
			if ok && !e.closing.Load() {
				if err := p.setEndpoint(next); err != nil {
					e.logf("UDP caminho %d: erro ao trocar endpoint: %v", i+2, err)
				} else {
					e.logf("UDP caminho %d: tentando %s", i+2, next)
				}
			}
			e.epMu.Unlock()
			misses[i] = 0
		}
		if e.addr4.IsValid() {
			p.probe(e.addr4, netip.MustParseAddr("1.1.1.1"))
		} else if e.addr6.IsValid() {
			p.probe(e.addr6, netip.MustParseAddr("2606:4700:4700::1111"))
		}
		misses[i]++
	}
}

// selectPath is called under natMu only for a new flow. Existing flows remain
// pinned to their selected exit, unless it stops responding.
func (e *Engine) selectPath(key portKey) uint8 {
	var active [maxPaths]uint8
	n := 0
	if !e.primaryHold.Load() {
		active[n] = 0 // primary path
		n++
	}
	now := time.Now()
	for i, p := range e.paths {
		if p != nil && p.active(now) {
			active[n] = uint8(i + 1)
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return active[(uint32(key.port)+uint32(key.proto)*257)%uint32(n)]
}

func (e *Engine) pathTun(index uint8) *splitTun {
	if index > 0 && int(index) <= len(e.paths) {
		p := e.paths[index-1]
		if p != nil && p.active(time.Now()) {
			return p.tun
		}
	}
	return e.tun
}

// Duplicate packets use another working path when possible, without changing
// the path pinned to the original flow.
func (e *Engine) duplicateTun(original uint8) *splitTun {
	var active [maxPaths]uint8
	n := 0
	if original != 0 && !e.primaryHold.Load() {
		active[n] = 0
		n++
	}
	now := time.Now()
	for i, p := range e.paths {
		if p != nil && uint8(i+1) != original && p.active(now) {
			active[n] = uint8(i + 1)
			n++
		}
	}
	if n == 0 {
		return e.pathTun(original)
	}
	return e.pathTun(active[(e.dupPath.Add(1)-1)%uint64(n)])
}
