//go:build windows

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

// A client engine starts pointed at a dead port; SetEndpoint must move it to a
// real WireGuard server on loopback (handshake confirmed) and undo a switch to
// a port where nothing answers.
func TestSetEndpointSwitchesLiveAndRevertsWithoutHandshake(t *testing.T) {
	cpriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvPort, deadPort, deadPort2 := freeUDPPort(t), freeUDPPort(t), freeUDPPort(t)

	srv := device.NewDevice(newSplitTun(1420), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer srv.Close()
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(spriv.Bytes()), srvPort, hex.EncodeToString(cpriv.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}

	b64 := base64.StdEncoding.EncodeToString
	conf, err := ParseConfig(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.9.0.1/32\n",
		b64(cpriv.Bytes()), b64(spriv.PublicKey().Bytes()), deadPort))
	if err != nil {
		t.Fatal(err)
	}
	loop := netip.MustParseAddr("127.0.0.1")
	dead := netip.AddrPortFrom(loop, deadPort)
	good := netip.AddrPortFrom(loop, srvPort)
	cli := device.NewDevice(newSplitTun(conf.MTU), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer cli.Close()
	if err := cli.IpcSet(conf.UAPI([]netip.AddrPort{dead})); err != nil {
		t.Fatal(err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	e := &Engine{conf: conf, dev: cli, pings: map[uint16]*pingState{0: {}}, logf: t.Logf}
	e.epCur.Store(&[]netip.AddrPort{dead})
	defer func(old time.Duration) { endpointSwitchWait = old }(endpointSwitchWait)
	endpointSwitchWait = 3 * time.Second

	if err := e.SetEndpoint(good); err != nil {
		t.Fatalf("switch to a working server: %v", err)
	}
	if got := e.eps()[0]; got != good {
		t.Fatalf("endpoint %v, want %v", got, good)
	}
	if e.pings[0].target != loop {
		t.Fatalf("direct ping target not updated: %v", e.pings[0].target)
	}
	if err := e.SetEndpoint(netip.AddrPortFrom(loop, deadPort2)); err == nil {
		t.Fatal("switch to a dead port must fail")
	}
	if got := e.eps()[0]; got != good {
		t.Fatalf("failed switch must revert to %v, got %v", good, got)
	}
	if err := e.SetEndpointString("not an address"); err == nil {
		t.Fatal("invalid input accepted")
	}
	if err := e.SetEndpointString(loop.String()); err != nil {
		t.Fatalf("bare IP keeps the current port: %v", err)
	}
}

func TestPingStateKeepsTheLastTenRepliesOnly(t *testing.T) {
	s := &pingState{}
	for i := 1; i <= 12; i++ {
		s.record(true, time.Duration(i)*time.Millisecond)
	}
	s.record(false, 0) // a timeout is not a latency sample
	if len(s.rtts) != 10 || s.rtts[0] != 3*time.Millisecond || s.rtts[9] != 12*time.Millisecond {
		t.Fatalf("rtts %v", s.rtts)
	}
	if got := medianRTT(s.rtts); got != 8*time.Millisecond {
		t.Fatalf("median %v", got)
	}
}

// Switching the primary to an endpoint an extra path holds swaps the two: the
// path takes over the primary's old endpoint and the connection stays up.
func TestSetEndpointSwapsWithExtraPathHoldingIt(t *testing.T) {
	cpriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvPort, deadPort := freeUDPPort(t), freeUDPPort(t)

	srv := device.NewDevice(newSplitTun(1420), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer srv.Close()
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(spriv.Bytes()), srvPort, hex.EncodeToString(cpriv.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	conf, err := ParseConfig(fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.9.0.1/32\n",
		b64(cpriv.Bytes()), b64(spriv.PublicKey().Bytes()), deadPort))
	if err != nil {
		t.Fatal(err)
	}
	loop := netip.MustParseAddr("127.0.0.1")
	dead := netip.AddrPortFrom(loop, deadPort)
	good := netip.AddrPortFrom(loop, srvPort)

	cli := device.NewDevice(newSplitTun(conf.MTU), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer cli.Close()
	if err := cli.IpcSet(conf.UAPI([]netip.AddrPort{dead})); err != nil {
		t.Fatal(err)
	}
	if err := cli.Up(); err != nil {
		t.Fatal(err)
	}
	// An extra path device that currently holds the server endpoint.
	// Its own key keeps it from racing the primary's handshakes at the server.
	pk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pconf := *conf
	pconf.PrivateKey = pk.Bytes()
	pd := device.NewDevice(newSplitTun(conf.MTU), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer pd.Close()
	if err := pd.IpcSet(pconf.UAPI([]netip.AddrPort{good})); err != nil {
		t.Fatal(err)
	}
	p := &udpPath{dev: pd, peerKey: hex.EncodeToString(spriv.PublicKey().Bytes()), tun: newSplitTun(1420)}
	p.endpoint.Store(&good)

	e := &Engine{conf: conf, dev: cli, pings: map[uint16]*pingState{0: {}}, logf: t.Logf}
	e.epCur.Store(&[]netip.AddrPort{dead})
	e.paths[0] = p
	defer func(old time.Duration) { endpointSwitchWait = old }(endpointSwitchWait)
	endpointSwitchWait = 3 * time.Second

	if err := e.SetEndpoint(good); err != nil {
		t.Fatalf("swap with extra path: %v", err)
	}
	if got := e.eps()[0]; got != good {
		t.Fatalf("primary endpoint %v, want %v", got, good)
	}
	if got := p.currentEndpoint(); got != dead {
		t.Fatalf("extra path endpoint %v, want the primary's old %v", got, dead)
	}
}
