//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func hopsTo(addrs ...string) []Hop {
	var out []Hop
	for i, a := range addrs {
		h := Hop{TTL: i + 1}
		if a != "" {
			h.Addr, h.RTT = netip.MustParseAddr(a), time.Duration(i+1)*time.Millisecond
		}
		out = append(out, h)
	}
	return out
}

func TestRouteLinesShowBothSegmentsMarksAndSilence(t *testing.T) {
	if got := strings.Join(routeLines(Stats{}), "\n"); !strings.Contains(got, "medindo a rota") {
		t.Fatalf("no measurement yet: %q", got)
	}
	s := Stats{Route: RouteTrace{
		At:       time.Now(),
		Endpoint: netip.MustParseAddr("162.159.192.1"),
		Dest:     netip.MustParseAddr("193.202.112.181"), DestIsGame: true,
		Direct: hopsTo("192.168.0.1", "", "162.159.192.1"),
		Tunnel: hopsTo("172.16.0.1", "203.0.113.5", "193.202.112.181"),
	}}
	got := strings.Join(routeLines(s), "\n")
	for _, want := range []string{
		"endpoint 162.159.192.1", "192.168.0.1", "162.159.192.1", "◀ endpoint",
		"══ túnel WireGuard", "endpoint → jogo 193.202.112.181", "172.16.0.1", "◀ jogo",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.Contains(got, " 2  *") {
		t.Errorf("a silent hop must show *:\n%s", got)
	}

	s.Route.DestIsGame, s.Route.Tunnel = false, nil
	got = strings.Join(routeLines(s), "\n")
	if !strings.Contains(got, "gateway do túnel") || !strings.Contains(got, "nenhum salto respondeu dentro do túnel") {
		t.Errorf("gateway-only and empty tunnel segment:\n%s", got)
	}
}

func TestRouteLinesCollapseLongPaths(t *testing.T) {
	var addrs []string
	for i := 1; i <= 18; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.0.%d", i))
	}
	s := Stats{Route: RouteTrace{At: time.Now(), Endpoint: netip.MustParseAddr("10.0.0.18"), Direct: hopsTo(addrs...)}}
	got := strings.Join(routeLines(s), "\n")
	if !strings.Contains(got, "saltos omitidos") || !strings.Contains(got, "10.0.0.1 ") || !strings.Contains(got, "10.0.0.18") {
		t.Fatalf("long path must keep the ends and drop the middle:\n%s", got)
	}
	if strings.Contains(got, "10.0.0.9 ") {
		t.Fatalf("middle hop should be collapsed:\n%s", got)
	}
}
