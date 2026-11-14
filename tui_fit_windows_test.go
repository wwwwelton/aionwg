//go:build windows

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func connectedModel(w, h int) model {
	m := newModel()
	m.eng = &Engine{}
	m.engName = "wgcf-profile.conf"
	m.since = time.Now()
	m.width, m.height = w, h
	m.configs = []string{"a.conf", "b.conf", "wgcf-profile.conf"}
	m.cursor = 2
	hops := make([]Hop, 12)
	for i := range hops {
		hops[i] = Hop{TTL: i + 1, Addr: netip.MustParseAddr("10.0.0.1"), RTT: time.Millisecond}
	}
	m.stats.Route = RouteTrace{At: time.Now(), Endpoint: netip.MustParseAddr("1.1.1.1"), Dest: netip.MustParseAddr("2.2.2.2"), Direct: hops, Tunnel: hops}
	m.stats.MirrorOn = true
	m.stats.MirrorAck = MirrorRTT{Last: 14 * time.Millisecond, Avg: 14 * time.Millisecond, N: 5}
	m.histPing = []float64{14, 15, 14, 16}
	for i := 0; i < 20; i++ {
		m.logs = append(m.logs, "linha de log")
	}
	return m
}

// The connected screen must fit the terminal using one of the compact layouts,
// without relying on the emergency clip at the end of View.
func TestViewFitsTerminalHeight(t *testing.T) {
	for _, sz := range [][2]int{{160, 40}, {100, 46}, {120, 50}} {
		m := connectedModel(sz[0], sz[1])
		fits := false
		for level := 0; level <= 3; level++ {
			fits = fits || lipgloss.Height(m.render(level)) <= sz[1]
		}
		if !fits {
			t.Errorf("%dx%d: no layout level fits", sz[0], sz[1])
		}
		if got := lipgloss.Height(m.View()); got > sz[1] {
			t.Errorf("%dx%d: view height %d exceeds the terminal", sz[0], sz[1], got)
		}
	}
}
