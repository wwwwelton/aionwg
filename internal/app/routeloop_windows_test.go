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
	return e, a, b, func() string { mu.Lock(); defer mu.Unlock(); return sb.String() }
}

