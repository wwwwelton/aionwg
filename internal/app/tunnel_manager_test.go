package app

import (
	"os"
	"path/filepath"
	"testing"
)

const tunnelManagerTestConfig = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

func TestTunnelManagerProfileOperations(t *testing.T) {
	dir := t.TempDir()
	manager := NewTunnelManager(dir)
	if err := os.WriteFile(filepath.Join(dir, "base.conf"), []byte(tunnelManagerTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := manager.Profile("base")
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Valid || profile.MTU != 1380 || profile.Endpoint != "203.0.113.10:51820" || profile.Keepalive != 25 {
		t.Fatalf("unexpected profile metadata: %+v", profile)
	}
	if err := manager.Duplicate("base.conf", "copy.conf"); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(filepath.Join(dir, "base.conf"))
	copy, _ := os.ReadFile(filepath.Join(dir, "copy.conf"))
	if string(original) != string(copy) {
		t.Fatal("duplicate changed the WireGuard profile")
	}
	if err := manager.Rename("copy.conf", "renamed.conf"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "renamed.conf")); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelManagerRejectsPathTraversal(t *testing.T) {
	if _, err := profileFilename(`..\secret`); err == nil {
		t.Fatal("path traversal name accepted")
	}
}
