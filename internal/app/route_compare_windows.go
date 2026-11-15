//go:build windows

package app

import (
	"fmt"
	"time"
)

func routeCandidates(s Stats, warpMultipath bool) []RouteCandidate {
	candidates := []RouteCandidate{
		{Kind: RouteDirect, Name: "Conexão direta", Measurement: pingMeasurement(s.PingGameDirect, "ICMP direto")},
		{Kind: RouteWireGuard, Name: "WireGuard ativo", Measurement: pingMeasurement(s.PingGame, "ICMP túnel")},
		{Kind: RouteWARP, Name: "WARP/WARP+ multipath", Measurement: warpMeasurement(s, warpMultipath)},
		{Kind: RouteRelay, Name: "Relay próprio", Measurement: RouteMeasurement{Transport: "não configurado"}},
	}
	return rankRouteCandidates(candidates)
}

func pingMeasurement(p PingResult, transport string) RouteMeasurement {
	return RouteMeasurement{
		At:        time.Now(),
		RTT:       p.RTT,
		P50:       valueOrDuration(p.P50, p.RTT),
		P95:       valueOrDuration(p.P95, p.RTT),
		Jitter:    p.Jitter,
		Loss:      p.Loss,
		Samples:   1,
		Transport: transport,
		Available: p.OK,
	}
}

func warpMeasurement(s Stats, enabled bool) RouteMeasurement {
	if !enabled {
		return RouteMeasurement{Transport: "multipath desativado"}
	}
	best := time.Duration(0)
	for _, path := range s.Paths {
		if path.Active && path.RTT > 0 && (best == 0 || path.RTT < best) {
			best = path.RTT
		}
	}
	if best == 0 {
		return RouteMeasurement{Transport: "sem caminho confirmado"}
	}
	return RouteMeasurement{At: time.Now(), RTT: best, P50: best, P95: best, Samples: 1, Transport: "sessão WARP gerenciada pelo AionWG", Available: true}
}

func routeCandidateText(candidate RouteCandidate) string {
	if !candidate.Measurement.Available {
		return fmt.Sprintf("N/A · %s", candidate.Measurement.Transport)
	}
	return fmt.Sprintf("RTT %v · P50 %v · P95 %v · jitter %v · perda %.1f%% · %s",
		candidate.Measurement.RTT.Round(time.Millisecond), candidate.Measurement.P50.Round(time.Millisecond), candidate.Measurement.P95.Round(time.Millisecond),
		candidate.Measurement.Jitter.Round(time.Millisecond), candidate.Measurement.Loss*100, candidate.Measurement.Transport)
}

func valueOrDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}
