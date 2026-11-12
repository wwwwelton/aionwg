package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullTunnelAllowed(t *testing.T) {
	c, _ := ParseConfig(sampleConf)
	ep := netip.MustParseAddr("203.0.113.10")
	al := FullTunnelAllowed(c, []netip.Addr{ep})
	in := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range al {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "56.124.121.12", "10.66.66.1", "223.255.255.255", "203.0.113.11"} {
		if !in(s) {
			t.Errorf("%s should be tunnelled", s)
		}
	}
	for _, s := range []string{"192.168.1.1", "10.1.1.1", "172.20.0.1", "239.255.255.250", "203.0.113.10", "127.0.0.1"} {
		if in(s) {
			t.Errorf("%s should NOT be tunnelled", s)
		}
	}
	if !in("2606:4700::1111") {
		t.Error("IPv6 must be captured (blocked) too")
	}
	t.Logf("%d prefixes", len(al))
}

// Writes the user's official-client configs when AIONWG_GEN is set.
func TestGenerateOfficial(t *testing.T) {
	src := os.Getenv("AIONWG_GEN")
	if src == "" {
		t.Skip()
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	ep, _ := ResolveEndpoint(c.Peers[0].Endpoint)
	eps := []netip.Addr{ep.Addr()}
	base := strings.TrimSuffix(filepath.Base(src), ".conf")
	out := os.Getenv("AIONWG_OUT")
	full := RenderOfficial(string(raw), "sistema inteiro (rede local fora do túnel)", FullTunnelAllowed(c, eps), true)
	var obs []netip.Addr
	for _, s := range strings.Split(os.Getenv("AIONWG_OBS"), ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			obs = append(obs, a)
		}
	}
	game := RenderOfficial(string(raw), "só AION 2 + Steam (por faixa de IP)", GameAllowed(c, obs, eps), false)
	os.WriteFile(filepath.Join(out, base+"-sistema.conf"), []byte(full), 0o600)
	os.WriteFile(filepath.Join(out, base+"-jogo.conf"), []byte(game), 0o600)
	for _, s := range []string{full, game} {
		if _, err := ParseConfig(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGameAllowedHasAionServer(t *testing.T) {
	c, _ := ParseConfig(sampleConf)
	al := GameAllowed(c, nil, nil)
	a := netip.MustParseAddr("193.202.112.161")
	for _, p := range al {
		if p.Contains(a) {
			return
		}
	}
	t.Fatal("AION 2 server not covered")
}

func TestUserFixedConfig(t *testing.T) {
	p := os.Getenv("AIONWG_CHECK")
	if p == "" {
		t.Skip()
	}
	raw, _ := os.ReadFile(p)
	c, err := ParseConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if c.MTU != 1280 || !c.Allowed(netip.MustParseAddr("193.202.112.161")) || !c.Allowed(netip.MustParseAddr("2606:4700::1")) {
		t.Fatal("unexpected")
	}
	if c.Allowed(netip.MustParseAddr("192.168.1.1")) || c.Allowed(netip.MustParseAddr("56.124.121.11")) {
		t.Fatal("LAN/endpoint must stay out")
	}
}
