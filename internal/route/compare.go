// Package route contains route ranking primitives independent of the TUI and Windows APIs.
package route

import (
	"sort"
	"time"
)

type Kind string

const (
	Direct    Kind = "DIRECT"
	WARP      Kind = "WARP/WARP+"
	WireGuard Kind = "WIREGUARD"
	Relay     Kind = "CUSTOM RELAY"
)

type Measurement struct {
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

type Candidate struct {
	Kind        Kind
	Name        string
	Measurement Measurement
	Locked      bool
}

func quality(m Measurement) float64 {
	if !m.Available {
		return 1e18
	}
	latency := m.P95
	if latency <= 0 {
		latency = m.RTT
	}
	return latency.Seconds()*1000 + m.Jitter.Seconds()*2000 + m.Loss*1000
}

func RankCandidates(candidates []Candidate) []Candidate {
	out := append([]Candidate(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := quality(out[i].Measurement), quality(out[j].Measurement)
		if left == right {
			return out[i].Kind < out[j].Kind
		}
		return left < right
	})
	return out
}

func ChooseCandidate(candidates []Candidate, current Kind, now, lastSwitch time.Time, cooldown time.Duration, minGain float64) (Candidate, bool) {
	ranked := RankCandidates(candidates)
	if len(ranked) == 0 || !ranked[0].Measurement.Available {
		return Candidate{}, false
	}
	var currentCandidate *Candidate
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
	gain := quality(currentCandidate.Measurement) - quality(ranked[0].Measurement)
	if gain < minGain {
		return *currentCandidate, false
	}
	return ranked[0], true
}
