//go:build windows

package app

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const probeTestConf = `[Interface]
PrivateKey = %s
Address = 172.16.0.2/32
[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 162.159.192.1:2408
`

func probeTestKey(c byte) string { return strings.Repeat(string(c), 43) + "=" }

func writeProbeTestConf(t *testing.T, path, priv, pub string) {
	t.Helper()
	body := strings.Replace(strings.Replace(probeTestConf, "%s", priv, 1), "%s", pub, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The probe identity must be a different key on the same server; reusing the
// live key would drop the live session. Nothing is picked automatically.
func TestSetProbeConfigNeedsAnotherAccountOnTheSameServer(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	src := t.TempDir()
	p := func(n string) string { return filepath.Join(src, n) }
	writeProbeTestConf(t, p("live.conf"), probeTestKey('A'), probeTestKey('S'))
	writeProbeTestConf(t, p("same.conf"), probeTestKey('A'), probeTestKey('S'))
	writeProbeTestConf(t, p("otherVPN.conf"), probeTestKey('B'), probeTestKey('T'))
	writeProbeTestConf(t, p("free.conf"), probeTestKey('C'), probeTestKey('S'))
	liveBytes, _ := os.ReadFile(p("live.conf"))
	live, err := ParseConfig(string(liveBytes))
	if err != nil {
		t.Fatal(err)
	}
	if savedProbeConf(live) != nil {
		t.Fatal("nothing is chosen automatically")
	}
	if _, err := setProbeConfig(p("otherVPN.conf"), live); err == nil {
		t.Fatal("a file for another server must be refused")
	}
	if savedProbeConf(live) != nil {
		t.Fatal("a refused file must not be stored")
	}
	// The same file as the live profile is accepted without an error and kept apart.
	if name, err := setProbeConfig(p("same.conf"), live); err != nil || name != "same.conf" {
		t.Fatalf("the same account must be accepted silently: name=%q err=%v", name, err)
	}
	if got := savedProbeConf(live); got == nil || string(got.PrivateKey) != string(live.PrivateKey) {
		t.Fatalf("expected the same-key copy, got %v", got)
	}
	name, err := setProbeConfig(`"`+p("free.conf")+`"`, live)
	if err != nil || name != "free.conf" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	got := savedProbeConf(live)
	if got == nil || string(got.PrivateKey) == string(live.PrivateKey) {
		t.Fatalf("expected the chosen identity, got %v", got)
	}
	if info, err := os.Stat(probeConfPath()); err != nil || info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("probe copy must stay private: %v %v", info, err)
	}
}

// On Cloudflare WARP the live key must not handshake from a second socket while
// the game runs; on other servers (several connections per key) it may.
func TestProbeConfWithTheLiveKeyIsHeldBackOnWarpDuringTheGame(t *testing.T) {
	e, a, _, _ := routeFixture(t) // the fixture has a game flow
	probeConfFn = func(live *WGConf) *WGConf { return live }
	if e.probeConf() == nil {
		t.Fatal("a non-WARP server accepts several connections per key")
	}
	e.epCur.Store(&[]netip.AddrPort{netip.MustParseAddrPort("162.159.192.1:2408")})
	if e.probeConf() != nil {
		t.Fatal("same key on WARP during the game would drop the live session")
	}
	e.nat = map[portKey]*natEntry{} // game stopped
	if e.probeConf() == nil {
		t.Fatal("with the game idle the probe may run")
	}
	_ = a
}
