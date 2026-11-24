package app

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	DefaultProbeInterval = 250 * time.Millisecond
	DefaultSwitchMargin  = 5.0  // ms
	DefaultFlowIdleSecs  = 120  // seconds
	DefaultMultipath     = 2
	ProbeTimeout         = 2 * time.Second
	LossWindow           = 50
	DeadAfter            = 3 * time.Second
	LossPenaltyMS        = 10.0 // ms penalty per 1% loss
)

// PinglessConfig holds the relay configuration (from TOML).
type PinglessConfig struct {
	PSK             string           `toml:"psk"`
	Multipath       int              `toml:"multipath"`
	ProbeIntervalMS int              `toml:"probe_interval_ms"`
	SwitchMarginMS  float64          `toml:"switch_margin_ms"`
	FlowIdleSecs    int              `toml:"flow_idle_secs"`
	Capture         PinglessCapture  `toml:"capture"`
	Exits           []PinglessExit   `toml:"exits"`
}

type PinglessCapture struct {
	Processes      []string `toml:"processes"`
	TunnelExisting bool     `toml:"tunnel_existing"`
}

type PinglessExit struct {
	Name   string          `toml:"name"`
	Routes []PinglessRoute `toml:"routes"`
}

type PinglessRoute struct {
	Name string `toml:"name"`
	Via  string `toml:"via"`  // host:port
	Bind string `toml:"bind"` // optional local IP
}

func ParsePinglessConfig(data string) (*PinglessConfig, error) {
	var cfg PinglessConfig
	if err := toml.Unmarshal([]byte(data), &cfg); err != nil {
		return nil, fmt.Errorf("erro lendo TOML Pingless: %w", err)
	}
	if cfg.Multipath <= 0 {
		cfg.Multipath = DefaultMultipath
	}
	if cfg.ProbeIntervalMS <= 0 {
		cfg.ProbeIntervalMS = 250
	}
	if cfg.SwitchMarginMS <= 0 {
		cfg.SwitchMarginMS = DefaultSwitchMargin
	}
	if cfg.FlowIdleSecs <= 0 {
		cfg.FlowIdleSecs = DefaultFlowIdleSecs
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("chave 'psk' é obrigatória no config Pingless")
	}
	if len(cfg.Exits) == 0 {
		return nil, fmt.Errorf("nenhum 'exits' configurado no Pingless")
	}
	for _, e := range cfg.Exits {
		if len(e.Routes) == 0 {
			return nil, fmt.Errorf("exit %q não possui rotas", e.Name)
		}
	}
	return &cfg, nil
}

func ReadPinglessConfigFile(path string) (*PinglessConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePinglessConfig(string(b))
}

// IsPinglessConfig checks if text has Pingless markers (psk = ..., [[exits]])
func IsPinglessConfig(text string) bool {
	return (strings.Contains(text, "psk") || strings.Contains(text, "PSK")) &&
		(strings.Contains(text, "exits") || strings.Contains(text, "routes"))
}

// RouteStats tracks RTT, jitter, and packet loss using RFC 6298 smoothing
type RouteStats struct {
	outstanding []probeEntry
	results     []bool // ring buffer up to LossWindow
	srtt        *float64
	rttvar      float64
	lastRTT     *float64
	lastAnswer  time.Time
	bytesUp     uint64
	bytesDown   uint64
}

type probeEntry struct {
	probe uint32
	sent  time.Time
}

func (s *RouteStats) OnProbeSent(probe uint32, now time.Time) {
	s.expire(now)
	s.outstanding = append(s.outstanding, probeEntry{probe: probe, sent: now})
}

func (s *RouteStats) OnProbeSendFailed(probe uint32) {
	for i, p := range s.outstanding {
		if p.probe == probe {
			s.outstanding = append(s.outstanding[:i], s.outstanding[i+1:]...)
			break
		}
	}
}

func (s *RouteStats) OnPong(probe uint32, now time.Time) (float64, bool) {
	idx := -1
	var sent time.Time
	for i, p := range s.outstanding {
		if p.probe == probe {
			idx = i
			sent = p.sent
			break
		}
	}
	if idx < 0 {
		return 0, false
	}
	s.outstanding = append(s.outstanding[:idx], s.outstanding[idx+1:]...)
	rtt := float64(now.Sub(sent).Microseconds()) / 1000.0 // in ms

	if s.srtt == nil {
		srttVal := rtt
		s.srtt = &srttVal
		s.rttvar = rtt / 2.0
	} else {
		s.rttvar = 0.75*s.rttvar + 0.25*math.Abs(*s.srtt-rtt)
		*s.srtt = 0.875*(*s.srtt) + 0.125*rtt
	}
	s.lastRTT = &rtt
	s.lastAnswer = now
	s.pushResult(true)
	return rtt, true
}

func (s *RouteStats) expire(now time.Time) {
	var remaining []probeEntry
	for _, p := range s.outstanding {
		if now.Sub(p.sent) >= ProbeTimeout {
			s.pushResult(false)
		} else {
			remaining = append(remaining, p)
		}
	}
	s.outstanding = remaining
}

func (s *RouteStats) pushResult(ok bool) {
	s.results = append(s.results, ok)
	if len(s.results) > LossWindow {
		s.results = s.results[len(s.results)-LossWindow:]
	}
}

func (s *RouteStats) LossPct() float64 {
	if len(s.results) == 0 {
		return 0
	}
	lost := 0
	for _, ok := range s.results {
		if !ok {
			lost++
		}
	}
	return float64(lost) * 100.0 / float64(len(s.results))
}

func (s *RouteStats) Alive(now time.Time) bool {
	return !s.lastAnswer.IsZero() && now.Sub(s.lastAnswer) < DeadAfter
}

func (s *RouteStats) Score(now time.Time) (float64, bool) {
	if !s.Alive(now) || s.srtt == nil {
		return 0, false
	}
	score := *s.srtt + 2.0*s.rttvar + s.LossPct()*LossPenaltyMS
	return score, true
}

// ReselectRoutes selects up to multipath active routes according to the Pingless hysteresis logic
func ReselectRoutes(
	candidateScores map[uint16]float64,
	currentActive []uint16,
	multipath int,
	switchMargin float64,
) []uint16 {
	// 1. Filter current active that are still alive
	var next []struct {
		pid   uint16
		score float64
	}
	for _, pid := range currentActive {
		if s, ok := candidateScores[pid]; ok {
			next = append(next, struct {
				pid   uint16
				score float64
			}{pid, s})
		}
	}

	// 2. Iterate candidates
	for pid, s := range candidateScores {
		already := false
		for _, item := range next {
			if item.pid == pid {
				already = true
				break
			}
		}
		if already {
			continue
		}

		if len(next) < multipath {
			next = append(next, struct {
				pid   uint16
				score float64
			}{pid, s})
			continue
		}

		// Find worst in next
		worstIdx := 0
		worstScore := next[0].score
		for i := 1; i < len(next); i++ {
			if next[i].score > worstScore {
				worstIdx = i
				worstScore = next[i].score
			}
		}

		// Replace if better by switchMargin
		if s+switchMargin < worstScore {
			next[worstIdx] = struct {
				pid   uint16
				score float64
			}{pid, s}
		}
	}

	res := make([]uint16, len(next))
	for i, item := range next {
		res[i] = item.pid
	}
	return res
}

// ResolvedPinglessRoute is a route with resolved address
type ResolvedPinglessRoute struct {
	ID   uint16
	Name string
	Via  netip.AddrPort
	Bind netip.Addr
}
