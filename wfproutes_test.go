package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func TestWFPRoutesPersistHostsWithoutChangingOtherPeers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.conf")
	raw := strings.Replace(sampleConf, "AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.0.0.0/8", 1)
	c, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Narrow the fixture independently of its original formatting.
	raw = RenderOfficial(raw, "fixture", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, true)
	c, err = ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &wfpRoutes{conf: c, path: path, apply: func(string) error { return nil }}
	for _, addr := range []string{"203.0.113.20", "2001:db8::20"} {
		if err := r.ensure(netip.MustParseAddr(addr)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConfig(string(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"203.0.113.20", "2001:db8::20", "10.1.2.3"} {
		if !got.Allowed(netip.MustParseAddr(addr)) {
			t.Fatalf("missing %s", addr)
		}
	}
	if got.Allowed(netip.MustParseAddr("203.0.113.21")) {
		t.Fatal("route expanded beyond one host")
	}
	if err := r.flush(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(b) {
		t.Fatal("unchanged destinations rewrote profile")
	}
}

func TestWFPRoutesFailedUpdateDoesNotAuthorizeDestination(t *testing.T) {
	c, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	c.Peers[0].AllowedIPs = nil
	r := &wfpRoutes{conf: c, apply: func(string) error { return errors.New("rejected") }}
	dst := netip.MustParseAddr("203.0.113.20")
	if err := r.ensure(dst); err == nil {
		t.Fatal("update failure was ignored")
	}
	if r.added[dst] {
		t.Fatal("failed route marked installed")
	}
}

func TestWFPRoutesAddsLiveWireGuardRoute(t *testing.T) {
	c, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	c.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tun := newSplitTun(1420)
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(c.UAPI([]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")})); err != nil {
		t.Fatal(err)
	}
	r := &wfpRoutes{conf: c, apply: dev.IpcSet}
	if err := r.ensure(netip.MustParseAddr("203.0.113.20")); err != nil {
		t.Fatal(err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(state, "allowed_ip=203.0.113.20/32\n") || !strings.Contains(state, "allowed_ip=10.0.0.0/8\n") {
		t.Fatal("live peer lost original route or did not acquire learned host")
	}
	_ = time.Second
}

func TestWFPRoutesRefusesLocalAndBypassDestinations(t *testing.T) {
	c, err := ParseConfig(sampleConf)
	if err != nil {
		t.Fatal(err)
	}
	c.Peers[0].AllowedIPs = nil
	r := &wfpRoutes{conf: c, apply: func(string) error {
		t.Fatal("local or bypass destination must never be added to WireGuard")
		return nil
	}}
	for _, addr := range []string{"127.0.0.1", "192.168.1.25", "169.254.1.1", "224.0.0.1", "fe80::1"} {
		if err := r.ensure(netip.MustParseAddr(addr)); err == nil {
			t.Fatalf("accepted non-routable destination %s", addr)
		}
	}
}

func TestWFPRoutesSyncsImportedAndExportedProfileCopies(t *testing.T) {
	dir := t.TempDir()
	raw := RenderOfficial(sampleConf, "fixture", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, true)
	c, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "wg01-jogo.conf")
	exported := filepath.Join(dir, "configs-wireguard-oficial", "wg01-jogo.conf")
	if err := os.MkdirAll(filepath.Dir(exported), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{primary, exported} {
		if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &wfpRoutes{conf: c, path: primary, paths: []string{exported}, apply: func(string) error { return nil }}
	if err := r.ensure(netip.MustParseAddr("198.51.100.77")); err != nil {
		t.Fatal(err)
	}
	if err := r.flush(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{primary, exported} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseConfig(string(b))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Allowed(netip.MustParseAddr("198.51.100.77")) {
			t.Fatalf("%s did not receive learned destination", p)
		}
	}
}
