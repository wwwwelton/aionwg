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

// The probe identity must differ from the live key and share the server key;
// reusing the live key would drop the live session.
func TestOtherProfileConfNeedsAnotherKeyOnTheSameServer(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	k := func(c byte) string { return strings.Repeat(string(c), 43) + "=" }
	write := func(name, priv, pub string) {
		if err := os.MkdirAll(configDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(strings.Replace(probeTestConf, "%s", priv, 1), "%s", pub, 1)
		if err := os.WriteFile(filepath.Join(configDir(), name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("live.conf", k('A'), k('S'))
	write("sameKey.conf", k('A'), k('S'))  // same identity: not isolated
	write("otherVPN.conf", k('B'), k('T')) // different server: not comparable
	live, err := readConfig("live.conf")
	if err != nil {
		t.Fatal(err)
	}
	if got := otherProfileConf(live, "live.conf"); got != nil {
		t.Fatalf("no isolated profile expected, got key %x", got.PrivateKey)
	}
	write("another.conf", k('C'), k('S'))
	got := otherProfileConf(live, "live.conf")
	if got == nil || string(got.PrivateKey) == string(live.PrivateKey) {
		t.Fatalf("expected the other WARP identity, got %v", got)
	}
}
