package app

import (
	"time"

	routepkg "aionwg/internal/route"
)

type RouteKind = routepkg.Kind
type RouteMeasurement = routepkg.Measurement
type RouteCandidate = routepkg.Candidate

const (
	RouteDirect    = routepkg.Direct
	RouteWARP      = routepkg.WARP
	RouteWireGuard = routepkg.WireGuard
	RouteRelay     = routepkg.Relay
)

func rankRouteCandidates(candidates []RouteCandidate) []RouteCandidate {
	return routepkg.RankCandidates(candidates)
}

func chooseRoute(candidates []RouteCandidate, current RouteKind, now, lastSwitch time.Time, cooldown time.Duration, minGain float64) (RouteCandidate, bool) {
	return routepkg.ChooseCandidate(candidates, current, now, lastSwitch, cooldown, minGain)
}
