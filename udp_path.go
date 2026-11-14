package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// udpPath owns an independent WireGuard session and its UDP socket. A path is
// usable only after an echo reply, not merely after a handshake.
type udpPath struct {
	tun      *splitTun
	dev      *device.Device
	port     uint16
	peerKey  string
	endpoint atomic.Pointer[netip.AddrPort]

	mu       sync.Mutex
	id, seq  uint16
	sent     time.Time
	src, dst netip.Addr
	lastRx   atomic.Int64
	rtt      atomic.Int64
}

func udpListenPort(ipc string) uint16 {
	for _, line := range strings.Split(ipc, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, _ := strconv.ParseUint(value, 10, 16)
			return uint16(port)
		}
	}
	return 0
}

func newUDPPath(conf *WGConf, endpoint netip.AddrPort, id uint16, inbound func([]byte)) (*udpPath, error) {
	if len(conf.Peers) != 1 || !endpoint.IsValid() {
		return nil, fmt.Errorf("caminho UDP exige um peer e endpoint válido")
	}
	p := &udpPath{id: id, peerKey: hex.EncodeToString(conf.Peers[0].PublicKey)}
	p.endpoint.Store(&endpoint)
	p.tun = newSplitTun(conf.MTU)
	p.tun.onInbound = func(pkt []byte) {
		if !p.receiveProbe(pkt) && inbound != nil {
			inbound(pkt)
		}
	}
	p.dev = device.NewDevice(p.tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	c := *conf
	c.ListenPort = 0 // each path must own a different UDP socket
	c.Peers = append([]PeerConf(nil), conf.Peers...)
	c.Peers[0].Keepalive = 0 // the staggered data-plane probes keep idle paths alive
	if err := p.dev.IpcSet(c.UAPI([]netip.AddrPort{endpoint})); err != nil {
		p.dev.Close()
		return nil, err
	}
	if err := p.dev.Up(); err != nil {
		p.dev.Close()
		return nil, err
	}
	state, err := p.dev.IpcGet()
	if err == nil {
		p.port = udpListenPort(state)
	}
	if err != nil || p.port == 0 {
		p.dev.Close()
		return nil, fmt.Errorf("porta UDP do caminho indisponível: %v", err)
	}
	return p, nil
}

func (p *udpPath) close() { p.dev.Close() }

func (p *udpPath) currentEndpoint() netip.AddrPort { return *p.endpoint.Load() }

func (p *udpPath) setEndpoint(endpoint netip.AddrPort) error {
	previous := p.currentEndpoint()
	// Publish before IpcSet so WinDivert excludes packets emitted by the device.
	p.endpoint.Store(&endpoint)
	if err := p.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", p.peerKey, endpoint)); err != nil {
		p.endpoint.Store(&previous)
		return err
	}
	p.mu.Lock()
	p.sent = time.Time{}
	p.mu.Unlock()
	p.lastRx.Store(0)
	return nil
}

func (p *udpPath) probe(src, dst netip.Addr) {
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.sent, p.src, p.dst = time.Now(), src, dst
	p.mu.Unlock()
	p.tun.inject(buildICMPEcho(src, dst, p.id, seq))
}

func (p *udpPath) receiveProbe(pkt []byte) bool {
	info, ok := parsePacket(pkt)
	if !ok || (info.proto != protoICMP && info.proto != protoICMPv6) {
		return false
	}
	id, seq, ok := parseICMPEchoReply(pkt, &info)
	if !ok || id != p.id {
		return false
	}
	p.mu.Lock()
	if !p.sent.IsZero() && seq == p.seq && info.src == p.dst && info.dst == p.src {
		now := time.Now()
		p.rtt.Store(int64(now.Sub(p.sent)))
		p.lastRx.Store(now.UnixNano())
		p.sent = time.Time{}
	}
	p.mu.Unlock()
	return true
}

func (p *udpPath) active(now time.Time) bool {
	last := p.lastRx.Load()
	return last != 0 && now.Sub(time.Unix(0, last)) < pathAliveFor
}
