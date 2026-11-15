package main

import (
	"sort"
	"time"
)

type RouteKind string

const (
	RouteDirect    RouteKind = "DIRECT"
	RouteWARP      RouteKind = "WARP/WARP+"
	RouteWireGuard RouteKind = "WIREGUARD"
	RouteRelay     RouteKind = "CUSTOM RELAY"
)

type RouteMeasurement struct {
	At        time.Time
	RTT       time.Duration
	Jitter    time.Duration
	P50       time.Duration
	P95       time.Duration
	Loss      float64
	Samples   int
	Transport string
	Available bool
}

type RouteCandidate struct {
	Kind        RouteKind
	Name        string
	Measurement RouteMeasurement
	Locked      bool
}

func routeQuality(m RouteMeasurement) float64 {
	if !m.Available {
		return 1e18
	}
	latency := m.P95
	if latency <= 0 {
		latency = m.RTT
	}
	return latency.Seconds()*1000 + m.Jitter.Seconds()*2000 + m.Loss*1000
}

func rankRouteCandidates(candidates []RouteCandidate) []RouteCandidate {
	out := append([]RouteCandidate(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := routeQuality(out[i].Measurement), routeQuality(out[j].Measurement)
		if left == right {
			return out[i].Kind < out[j].Kind
		}
		return left < right
	})
	return out
}

func chooseRoute(candidates []RouteCandidate, current RouteKind, now, lastSwitch time.Time, cooldown time.Duration, minGain float64) (RouteCandidate, bool) {
	ranked := rankRouteCandidates(candidates)
	if len(ranked) == 0 || !ranked[0].Measurement.Available {
		return RouteCandidate{}, false
	}
	var currentCandidate *RouteCandidate
	for i := range ranked {
		if ranked[i].Kind == current {
			currentCandidate = &ranked[i]
			break
		}
	}
	if currentCandidate == nil {
		return ranked[0], !ranked[0].Locked
	}
	if currentCandidate.Locked || ranked[0].Kind == current || ranked[0].Locked {
		return *currentCandidate, false
	}
	if !lastSwitch.IsZero() && now.Sub(lastSwitch) < cooldown {
		return *currentCandidate, false
	}
	gain := routeQuality(currentCandidate.Measurement) - routeQuality(ranked[0].Measurement)
	if gain < minGain {
		return *currentCandidate, false
	}
	return ranked[0], true
}
