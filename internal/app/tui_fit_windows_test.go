//go:build windows

package app

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
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
	m.stats.Paths = []udpPathStatus{
		{Endpoint: netip.MustParseAddrPort("162.159.192.1:2408"), Active: true},
		{Endpoint: netip.MustParseAddrPort("188.114.96.1:2408"), Active: true, RTT: 15 * time.Millisecond, Age: 31 * time.Second},
		{Endpoint: netip.MustParseAddrPort("188.114.97.1:2408")},
		{Endpoint: netip.MustParseAddrPort("188.114.98.1:2408")},
	}
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
		view := m.View()
		if got := lipgloss.Height(view); got > sz[1] {
			t.Errorf("%dx%d: view height %d exceeds the terminal", sz[0], sz[1], got)
		}
		for _, path := range m.stats.Paths {
			if !strings.Contains(view, path.Endpoint.String()) {
				t.Errorf("%dx%d: endpoint %s is not visible", sz[0], sz[1], path.Endpoint)
			}
		}
	}
}

func TestModernNavigationMappings(t *testing.T) {
	tests := map[string]uiScreen{
		"f1": screenDashboard, "f2": screenProcesses, "f3": screenTunnels,
		"f4": screenRoutes, "f5": screenWFP, "f6": screenUDP,
		"f7": screenWarp, "f8": screenLatency, "f9": screenDiagnostics,
		"f10": screenSettings,
	}
	for key, want := range tests {
		got, ok := screenForFunctionKey(key)
		if !ok || got != want {
			t.Errorf("%s: got %v, %v; want %v, true", key, got, ok, want)
		}
	}
}

func TestCommandPaletteFiltersWithoutChangingActions(t *testing.T) {
	m := model{input: textinput.New()}
	m.input.SetValue("warp")
	items := m.filteredCommands()
	if len(items) != 1 || items[0].name != "WARP e endpoints" {
		t.Fatalf("filtered commands = %#v", items)
	}
}
