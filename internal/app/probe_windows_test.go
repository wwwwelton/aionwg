//go:build windows

package app

import (
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
	for _, bad := range []string{"same.conf", "otherVPN.conf"} {
		if _, err := setProbeConfig(p(bad), live); err == nil {
			t.Fatalf("%s must be refused", bad)
		}
	}
	if savedProbeConf(live) != nil {
		t.Fatal("a refused file must not be stored")
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
	// Chosen file stops matching the live profile (user switched profile): unusable.
	writeProbeTestConf(t, p("live2.conf"), probeTestKey('C'), probeTestKey('S'))
	b2, _ := os.ReadFile(p("live2.conf"))
	live2, _ := ParseConfig(string(b2))
	if savedProbeConf(live2) != nil {
		t.Fatal("the live key must never be used as the probe identity")
	}
}
