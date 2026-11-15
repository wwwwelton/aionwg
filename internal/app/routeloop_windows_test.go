//go:build windows

package app

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Two real WireGuard servers on loopback (127.0.0.1 and 127.0.0.2) stand for two
// routes. Direct legs and game pings are simulated, so the whole monitor flow
// (pick, switch with a real handshake, compare game ping, keep or revert) runs
// without any network.
func routeFixture(t *testing.T) (e *Engine, a, b netip.AddrPort, logs func() string) {
	t.Helper()
	cpriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hx, b64 := hex.EncodeToString, base64.StdEncoding.EncodeToString
	aPort, bPort := freeUDPPort(t), freeUDPPort(t)
	for _, port := range []uint16{aPort, bPort} {
		srv := device.NewDevice(newSplitTun(1420), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		t.Cleanup(srv.Close)
		if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
			hx(spriv.Bytes()), port, hx(cpriv.PublicKey().Bytes()))); err != nil {
			t.Fatal(err)
		}
		if err := srv.Up(); err != nil {
			t.Fatal(err)
		}
	}
	a = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), aPort)
	b = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), bPort)
	conf, err := ParseConfig(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 10.9.0.1/32\n",
		b64(cpriv.Bytes()), b64(spriv.PublicKey().Bytes()), a))
	if err != nil {
		t.Fatal(err)
	}
	cli := device.NewDevice(newSplitTun(conf.MTU), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(cli.Close)
	if err := cli.IpcSet(conf.UAPI([]netip.AddrPort{a})); err != nil {
		t.Fatal(err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sb strings.Builder
	e = &Engine{
		conf: conf, dev: cli, stop: make(chan struct{}), addr4: netip.MustParseAddr("10.9.0.2"),
		pings: map[uint16]*pingState{0: {}, pingIDGame: {}},
		nat:   map[portKey]*natEntry{{protoTCP, 1}: {remote: netip.MustParseAddr("203.0.113.50"), game: true, last: time.Now().Add(time.Hour)}},
		logf: func(f string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(&sb, f+"\n", args...)
		},
	}
	e.epCur.Store(&[]netip.AddrPort{a})
	e.learned = map[netip.AddrPort]bool{a: true, b: true}
	prev := probeConfFn
	probeConfFn = func(*WGConf) *WGConf { return nil } // no other profile: tests never read the user's
	t.Cleanup(func() { probeConfFn = prev })
	return e, a, b, func() string { mu.Lock(); defer mu.Unlock(); return sb.String() }
}

func runRouteLoop(t *testing.T, gameViaB time.Duration) (final netip.AddrPort, a, b netip.AddrPort, logs string) {
	e, a, b, getLogs := routeFixture(t)
	defer func(ev, st, rc, fc, sw time.Duration, p func(netip.Addr) (time.Duration, bool)) {
		routeEvery, routeSettle, routeCooldown, failCooldown, endpointSwitchWait, legProbe = ev, st, rc, fc, sw, p
	}(routeEvery, routeSettle, routeCooldown, failCooldown, endpointSwitchWait, legProbe)
	routeEvery, routeSettle, routeCooldown, failCooldown, endpointSwitchWait = 100*time.Millisecond, 600*time.Millisecond, time.Minute, time.Minute, 3*time.Second
	legProbe = func(x netip.Addr) (time.Duration, bool) {
		if x == a.Addr() {
			return 20 * time.Millisecond, true
		}
		return 10 * time.Millisecond, true
	}
	done := make(chan struct{})
	go func() { // the game ping through whichever route is current
		defer close(done)
		for {
			select {
			case <-e.stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			rtt := 30 * time.Millisecond
			if e.eps()[0] == b {
				rtt = gameViaB
			}
			e.pingMu.Lock()
			e.pings[pingIDGame].record(true, rtt)
			e.pingMu.Unlock()
		}
	}()
	time.Sleep(300 * time.Millisecond) // enough samples before the first tick
	go e.routeLoop()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(getLogs(), "mantida") && !strings.Contains(getLogs(), "voltando para") {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	close(e.stop)
	<-done
	return e.eps()[0], a, b, getLogs()
}

func TestRouteLoopKeepsTheRouteWhenGamePingImproves(t *testing.T) {
	final, _, b, logs := runRouteLoop(t, 20*time.Millisecond)
	if final != b || !strings.Contains(logs, "mantida") {
		t.Fatalf("expected to stay on %v with 'mantida'; final=%v\n%s", b, final, logs)
	}
}

func TestRouteLoopRevertsWhenGamePingDoesNotImprove(t *testing.T) {
	final, a, _, logs := runRouteLoop(t, 45*time.Millisecond)
	if final != a || !strings.Contains(logs, "voltando para") {
		t.Fatalf("expected to revert to %v; final=%v\n%s", a, final, logs)
	}
}

// A faster-looking endpoint whose separate handshake test fails must never
// receive the live tunnel.
func TestRouteLoopDoesNotSwitchWhenTheSeparateHandshakeFails(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	e, a, _, getLogs := routeFixture(t)
	dead := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.3"), freeUDPPort(t)) // nothing listens
	e.learned = map[netip.AddrPort]bool{a: true, dead: true}
	e.profile = "p.conf"
	if err := saveRoute(routesPath(), e.profile, dead); err != nil {
		t.Fatal(err)
	}
	probeConfFn = func(live *WGConf) *WGConf { return live } // stands for another identity
	defer func(ev time.Duration, p func(netip.Addr) (time.Duration, bool)) { routeEvery, legProbe = ev, p }(routeEvery, legProbe)
	routeEvery = 100 * time.Millisecond
	legProbe = func(x netip.Addr) (time.Duration, bool) {
		if x == a.Addr() {
			return 20 * time.Millisecond, true
		}
		return 5 * time.Millisecond, true
	}
	go func() { // enough game pings for the baseline
		for {
			select {
			case <-e.stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			e.pingMu.Lock()
			e.pings[pingIDGame].record(true, 30*time.Millisecond)
			e.pingMu.Unlock()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	go e.routeLoop()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(getLogs(), "falhou no handshake de teste") {
		time.Sleep(50 * time.Millisecond)
	}
	close(e.stop)
	if !strings.Contains(getLogs(), "falhou no handshake de teste") {
		t.Fatalf("expected the separate handshake test to fail:\n%s", getLogs())
	}
	if got := e.eps()[0]; got != a {
		t.Fatalf("live endpoint changed to %v:\n%s", got, getLogs())
	}
	if e.learned[dead] {
		t.Fatal("an endpoint that failed the isolated test must be forgotten")
	}
	for _, ep := range loadRoutes(routesPath(), e.profile) {
		if ep == dead {
			t.Fatal("the failed endpoint must be removed from the saved routes")
		}
	}
	if !loadBad(routesPath(), e.profile, time.Now())[dead.Addr()] {
		t.Fatal("the failed endpoint must be marked bad")
	}
}
