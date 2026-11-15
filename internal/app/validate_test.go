package app

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// AIONWG_VALIDATE=dir: every .conf there must parse and route sanely.
func TestValidateDir(t *testing.T) {
	dir := os.Getenv("AIONWG_VALIDATE")
	if dir == "" {
		t.Skip()
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		c, err := ParseConfig(string(raw))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		chk := func(ip string) bool { return c.Allowed(netip.MustParseAddr(ip)) }
		t.Logf("%-28s MTU=%d DNS=%v jogo=%v loja/API=%v LAN=%v endpoint=%v IPv6=%v", filepath.Base(f), c.MTU, c.DNS,
			chk("193.202.112.161"), chk("216.107.254.84"), chk("192.168.0.1"), chk("56.124.121.11"), chk("2606:4700::1"))
	}
}
