//go:build windows

package main

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// coloCity names the Cloudflare colo codes seen for WARP endpoints in Brazil.
var coloCity = map[string]string{
	"cwb": "Curitiba",
	"gru": "São Paulo",
	"gig": "Rio de Janeiro",
	"bsb": "Brasília",
	"poa": "Porto Alegre",
	"rec": "Recife",
	"for": "Fortaleza",
}

// coloLabel turns an id.server answer ("cwb02") into "cwb02 · Curitiba".
// Unknown codes are shown as they are.
func coloLabel(colo string) string {
	code := strings.ToLower(strings.TrimSpace(colo))
	if code == "" {
		return "localização desconhecida"
	}
	if len(code) >= 3 {
		if city, ok := coloCity[code[:3]]; ok {
			return code + " · " + city
		}
	}
	return code
}

// endpointRow is one entry of the endpoint picker. rtt is zero when the
// endpoint has not been measured yet.
type endpointRow struct {
	ep      netip.AddrPort
	label   string
	rtt     time.Duration
	current bool
}

// endpointStats keeps what the picker shows per endpoint. It is package level
// because it describes the endpoints, not one engine run.
var endpointStats = struct {
	sync.Mutex
	colo map[netip.AddrPort]string
	rtt  map[netip.AddrPort]time.Duration
}{
	colo: map[netip.AddrPort]string{},
	rtt:  map[netip.AddrPort]time.Duration{},
}

// noteEndpointLoc remembers the colo answered through ep.
func noteEndpointLoc(ep netip.AddrPort, colo string) {
	if strings.TrimSpace(colo) == "" {
		return
	}
	endpointStats.Lock()
	defer endpointStats.Unlock()
	endpointStats.colo[ep] = colo
}

// noteEndpointRTT remembers the last measured RTT through ep.
func noteEndpointRTT(ep netip.AddrPort, rtt time.Duration) {
	if rtt <= 0 {
		return
	}
	endpointStats.Lock()
	defer endpointStats.Unlock()
	endpointStats.rtt[ep] = rtt
}

// endpointRows lists the endpoints proven by a handshake, current one included,
// sorted by address.
func (e *Engine) endpointRows() []endpointRow {
	cur := e.eps()[0]
	seen := map[netip.AddrPort]bool{cur: true}
	eps := []netip.AddrPort{cur}
	for _, ep := range e.learnedList() {
		if !seen[ep] {
			seen[ep] = true
			eps = append(eps, ep)
		}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].String() < eps[j].String() })

	endpointStats.Lock()
	defer endpointStats.Unlock()
	rows := make([]endpointRow, 0, len(eps))
	for _, ep := range eps {
		label := "localização desconhecida"
		if colo, ok := endpointStats.colo[ep]; ok {
			label = coloLabel(colo)
		}
		rows = append(rows, endpointRow{ep: ep, label: label, rtt: endpointStats.rtt[ep], current: ep == cur})
	}
	return rows
}
