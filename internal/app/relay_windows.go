//go:build windows

package app

import (
	"fmt"
	"strings"
	"time"
)

func (e *Engine) relayLoop(relays []string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		e.measureRelays(relays)
		select {
		case <-e.stop:
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) measureRelays(relays []string) {
	candidates := make([]RouteCandidate, 0, len(relays))
	for _, raw := range relays {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		candidate := RouteCandidate{Kind: RouteRelay, Name: raw}
		endpoint, err := ResolveEndpoint(raw)
		if err != nil {
			candidate.Measurement.Transport = "relay inválido: " + err.Error()
			candidates = append(candidates, candidate)
			continue
		}
		candidate.Measurement = RouteMeasurement{At: time.Now(), Transport: "ICMP direto até relay " + endpoint.String()}
		if rtt, ok := icmpMedian(endpoint.Addr()); ok {
			candidate.Measurement.RTT = rtt
			candidate.Measurement.P50 = rtt
			candidate.Measurement.P95 = rtt
			candidate.Measurement.Samples = 5
			candidate.Measurement.Available = true
		} else {
			candidate.Measurement.Transport = fmt.Sprintf("sem resposta ICMP em %s", endpoint)
		}
		candidates = append(candidates, candidate)
	}
	e.relayMu.Lock()
	e.relayCandidates = candidates
	e.relayMu.Unlock()
}

func parseRelayEndpoints(value string) ([]string, error) {
	var out []string
	seen := map[string]struct{}{}
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		endpoint, err := ResolveEndpoint(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", raw, err)
		}
		canonical := endpoint.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return out, nil
}
