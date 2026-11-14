//go:build windows

package main

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const (
	geoPort      = 54053 // our UDP source port for exit queries
	geoRetryWait = 30 * time.Second
)

var geoResolver = netip.MustParseAddr("1.1.1.1")

// scanLoop runs every discoverEvery: it keeps the exit location current and,
// with the best-endpoint option, looks for a better endpoint while the game is
// idle. Handshake probes stay idle-only: a throwaway handshake with the same
// key makes the server talk to the probe's socket until the live session
// speaks again. Each candidate is probed at most once (learned or discarded
// for days), so a short period does not turn into a handshake burst.
func (e *Engine) scanLoop(best bool) {
	tk := time.NewTicker(discoverEvery)
	defer tk.Stop()
	var tried time.Time
	for {
		select {
		case <-e.stop:
			return
		case <-tk.C:
		}
		if e.closing.Load() {
			return
		}
		if x := e.exit.Load(); (x == nil || x.Endpoint != e.eps()[0]) && time.Since(tried) >= geoRetryWait {
			tried = time.Now()
			e.refreshExit()
		}
		if best && !e.gameServer().IsValid() {
			e.discoverIdle()
		}
	}
}

// geoAsk sends one CHAOS TXT query through the tunnel and waits for the answer.
func (e *Engine) geoAsk(name string) (string, bool) {
	src, ok := e.tunAddr(false)
	if !ok {
		return "", false
	}
	e.geoMu.Lock()
	if e.geoWait == nil {
		e.geoWait = map[uint16]chan string{}
	}
	e.geoSeq++
	id := e.geoSeq
	ch := make(chan string, 1)
	e.geoWait[id] = ch
	e.geoMu.Unlock()
	defer func() {
		e.geoMu.Lock()
		delete(e.geoWait, id)
		e.geoMu.Unlock()
	}()
	e.tun.inject(buildUDP4(src, geoResolver, geoPort, 53, buildChaosTXT(name, id)))
	select {
	case s := <-ch:
		return s, true
	case <-time.After(2 * time.Second):
	case <-e.stop:
	}
	return "", false
}

// geoReply delivers an inbound answer to the query waiting for it.
func (e *Engine) geoReply(pkt []byte, p *pktInfo) {
	n := pktLen(pkt, p)
	if p.v6 || p.l4+8+2 > n {
		return
	}
	dns := pkt[p.l4+8 : n]
	id := binary.BigEndian.Uint16(dns)
	e.geoMu.Lock()
	ch := e.geoWait[id]
	e.geoMu.Unlock()
	if ch == nil {
		return
	}
	if s, ok := parseChaosTXT(dns, id); ok {
		select {
		case ch <- s:
		default:
		}
	}
}

// refreshExit measures where the tunnel exits through the current endpoint.
func (e *Engine) refreshExit() {
	ep := e.eps()[0]
	ip, okIP := e.geoAsk("whoami.cloudflare")
	colo, okColo := e.geoAsk("id.server")
	if !okIP && !okColo {
		return
	}
	x := &ExitInfo{IP: ip, Colo: colo, Endpoint: ep, At: time.Now()}
	if okColo {
		noteEndpointLoc(ep, colo)
	}
	if okIP {
		if city, cc, err := geoIPLookup(newTestClient(), ip); err == nil {
			x.City, x.Country = city, cc
		}
	}
	e.exit.Store(x)
	e.routeLog("saída: %s", x.String())
}

func (x ExitInfo) String() string {
	s := x.Colo
	if x.City != "" {
		if s != "" {
			s += " · "
		}
		s += x.City + ", " + x.Country
	}
	if x.IP != "" {
		s += " · " + x.IP
	}
	return s + " (via endpoint " + x.Endpoint.Addr().String() + ")"
}
