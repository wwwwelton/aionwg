//go:build windows

package app

import (
	"fmt"
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
// endpoint has not been measured yet; path names the extra connection using it.
type endpointRow struct {
	ep      netip.AddrPort
	label   string
	rtt     time.Duration
	current bool
	path    string
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

// endpointRows lists the endpoints proven by a handshake, the current one and
// the endpoints of the extra connections, sorted by address.
func (e *Engine) endpointRows() []endpointRow {
	cur := e.eps()[0]
	seen := map[netip.AddrPort]bool{cur: true}
	eps := []netip.AddrPort{cur}
	add := func(ep netip.AddrPort) {
		if !seen[ep] {
			seen[ep] = true
			eps = append(eps, ep)
		}
	}
	for _, ep := range e.learnedList() {
		add(ep)
	}
	paths := map[netip.AddrPort]string{}
	now := time.Now()
	for i, p := range e.paths {
		if p == nil {
			continue
		}
		ep := p.currentEndpoint()
		state := "sem resposta"
		if p.active(now) {
			state = "ativo " + time.Duration(p.rtt.Load()).Round(time.Millisecond).String()
		}
		paths[ep] = fmt.Sprintf("caminho %d · %s", i+2, state)
		add(ep)
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
		rows = append(rows, endpointRow{ep: ep, label: label, rtt: endpointStats.rtt[ep], current: ep == cur, path: paths[ep]})
	}
	return rows
}

// endpointCandidates lists the WARP endpoints the path search is still trying
// that are not in rows yet, sorted by address.
func (e *Engine) endpointCandidates(rows []endpointRow) []netip.AddrPort {
	have := make(map[netip.AddrPort]bool, len(rows))
	for _, r := range rows {
		have[r.ep] = true
	}
	var out []netip.AddrPort
	for _, ep := range pathPool(e.eps()[0], e.learnedList()) {
		if !have[ep] {
			out = append(out, ep)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
