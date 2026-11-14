//go:build windows

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestUDPPathsStartThreeDistinctAdditionalSockets(t *testing.T) {
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	primary := netip.MustParseAddrPort("162.159.192.1:2408")
	e := &Engine{
		conf: &WGConf{PrivateKey: client.Bytes(), MTU: 1420, Peers: []PeerConf{{
			PublicKey:  server.PublicKey().Bytes(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}}},
		logf: func(string, ...any) {},
	}
	e.epCur.Store(&[]netip.AddrPort{primary})
	if err := e.startUDPPaths(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range e.paths {
			if p != nil {
				p.close()
			}
		}
	})
	endpoints := map[netip.AddrPort]bool{primary: true}
	ports := map[uint16]bool{}
	for _, p := range e.paths {
		if p == nil || p.port == 0 || ports[p.port] || endpoints[p.currentEndpoint()] {
			t.Fatalf("missing or repeated endpoint/socket: %#v", p)
		}
		ports[p.port], endpoints[p.currentEndpoint()] = true, true
	}
	if len(endpoints) != 4 {
		t.Fatalf("got %d distinct endpoints", len(endpoints))
	}
}

func TestUDPPathsRouteFlowsAndCopiesOnlyToResponsiveTunnels(t *testing.T) {
	e := &Engine{tun: newSplitTun(1420)}
	for i := range e.paths {
		p := &udpPath{tun: newSplitTun(1420)}
		p.lastRx.Store(time.Now().UnixNano())
		e.paths[i] = p
	}
	seen := map[uint8]bool{}
	for port := uint16(40000); port < 40016; port++ {
		path := e.selectPath(portKey{proto: protoUDP, port: port})
		seen[path] = true
		tun := e.pathTun(path)
		tun.inject([]byte{byte(path)})
		if got := <-tun.in; len(got) != 1 || got[0] != byte(path) {
			t.Fatalf("path %d got %v", path, got)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("flows did not use four active paths: %v", seen)
	}
	copies := map[*splitTun]bool{}
	for range 3 {
		copies[e.duplicateTun(0)] = true
	}
	if len(copies) != 3 || copies[e.tun] {
		t.Fatalf("copies did not use the three other paths: %v", copies)
	}
	e.paths[0].lastRx.Store(0)
	if got := e.pathTun(1); got != e.tun {
		t.Fatal("unresponsive path did not fall back to the primary")
	}
}

func TestUDPPathsCaptureDistributesGameFlows(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("203.0.113.10")
	owner := &ownerTracker{cache: map[portKey]ownerEntry{}}
	e := &Engine{
		conf:   &WGConf{Peers: []PeerConf{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}},
		addr4:  netip.MustParseAddr("172.16.0.2"),
		tun:    newSplitTun(1420),
		owner:  owner,
		mirror: newMirror(false, func(string, ...any) {}),
		nat:    make(map[portKey]*natEntry),
	}
	defer e.mirror.Close()
	e.epCur.Store(&[]netip.AddrPort{netip.MustParseAddrPort("162.159.192.1:2408")})
	for i := range e.paths {
		p := &udpPath{port: uint16(41000 + i), tun: newSplitTun(1420)}
		ep := netip.AddrPortFrom(netip.AddrFrom4([4]byte{188, 114, byte(96 + i), 1}), 2408)
		p.endpoint.Store(&ep)
		p.lastRx.Store(time.Now().UnixNano())
		e.paths[i] = p
	}
	for port := uint16(40000); port < 40016; port++ {
		key := portKey{proto: protoUDP, port: port}
		owner.cache[key] = ownerEntry{class: classGame, expires: time.Now().Add(time.Minute)}
		pkt := buildUDP4(src, dst, port, 7000, []byte("game"))
		if !e.capture(pkt, &divertAddress{}) {
			t.Fatalf("game packet from port %d bypassed the tunnel", port)
		}
	}
	tunnels := []*splitTun{e.tun, e.paths[0].tun, e.paths[1].tun, e.paths[2].tun}
	for i, tun := range tunnels {
		if len(tun.in) == 0 {
			t.Fatalf("no game packets reached path %d", i+1)
		}
		for len(tun.in) > 0 {
			pkt := <-tun.in
			info, ok := parsePacket(pkt)
			if !ok || info.src != e.addr4 || info.dst != dst {
				t.Fatalf("path %d received malformed or untranslated packet", i+1)
			}
			putPktBuf(pkt)
		}
	}
}

func TestUDPPathsDuplicateWorkerUsesOtherTunnels(t *testing.T) {
	e := &Engine{
		tun:    newSplitTun(1420),
		udpDup: newUDPDuplicator[uint8](16, true),
		stop:   make(chan struct{}),
	}
	for i := range e.paths {
		p := &udpPath{tun: newSplitTun(1420)}
		p.lastRx.Store(time.Now().UnixNano())
		e.paths[i] = p
	}
	e.udpDup.setRatio(1, 3)
	e.wg.Add(1)
	go e.runUDPDuplicateWorker()
	defer func() {
		close(e.stop)
		e.wg.Wait()
	}()
	e.udpDup.offer([]byte("duplicate"), 0)
	for i, path := range e.paths {
		select {
		case pkt := <-path.tun.in:
			if string(pkt) != "duplicate" {
				t.Fatalf("path %d received %q", i+2, pkt)
			}
			putPktBuf(pkt)
		case <-time.After(2 * time.Second):
			t.Fatalf("path %d received no duplicate", i+2)
		}
	}
}

func TestUDPPathFailureKeepsTheFlowOnTheFallback(t *testing.T) {
	src := netip.MustParseAddr("192.0.2.10")
	dst := netip.MustParseAddr("203.0.113.10")
	key := portKey{proto: protoUDP, port: 40000}
	e := &Engine{
		conf:  &WGConf{Peers: []PeerConf{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}},
		addr4: netip.MustParseAddr("172.16.0.2"),
		tun:   newSplitTun(1420),
		owner: &ownerTracker{cache: map[portKey]ownerEntry{key: {class: classApp, expires: time.Now().Add(time.Minute)}}},
		nat:   map[portKey]*natEntry{key: {remote: dst, remotePort: 7000, path: 1}},
	}
	e.epCur.Store(&[]netip.AddrPort{netip.MustParseAddrPort("162.159.192.1:2408")})
	p := &udpPath{port: 40111, tun: newSplitTun(1420)}
	ep := netip.MustParseAddrPort("188.114.96.1:2408")
	p.endpoint.Store(&ep)
	e.paths[0] = p
	packet := buildUDP4(src, dst, key.port, 7000, []byte("game"))
	for i := 0; i < 2; i++ {
		if i == 1 {
			p.lastRx.Store(time.Now().UnixNano())
		}
		if !e.capture(packet, &divertAddress{}) {
			t.Fatal("packet did not enter the tunnel")
		}
		select {
		case pkt := <-e.tun.in:
			putPktBuf(pkt)
		default:
			t.Fatal("flow moved away from its primary fallback")
		}
	}
	select {
	case <-p.tun.in:
		t.Fatal("flow moved back when the old path recovered")
	default:
	}
}

func TestUDPPathSocketsAreNotRecaptured(t *testing.T) {
	e := &Engine{tun: newSplitTun(1420)}
	p := &udpPath{port: 40111, tun: newSplitTun(1420)}
	ep := netip.MustParseAddrPort("188.114.96.1:2408")
	p.endpoint.Store(&ep)
	e.paths[0] = p
	for _, packet := range [][]byte{
		buildUDP4(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.1"), 40111, 2408, []byte("wg")),
		buildUDP4(netip.MustParseAddr("192.0.2.1"), ep.Addr(), 40112, ep.Port(), []byte("wg")),
	} {
		if e.capture(packet, &divertAddress{}) {
			t.Fatal("WireGuard path packet was recaptured")
		}
	}
}

func TestUDPPathsStatusShowsUnresponsivePaths(t *testing.T) {
	statuses := []udpPathStatus{
		{Endpoint: netip.MustParseAddrPort("162.159.192.1:2408"), Active: true},
		{Endpoint: netip.MustParseAddrPort("188.114.96.1:2408"), Active: true, RTT: 16 * time.Millisecond, Age: 30 * time.Second},
		{Endpoint: netip.MustParseAddrPort("188.114.97.1:2408")},
		{Endpoint: netip.MustParseAddrPort("188.114.98.1:2408")},
	}
	text := udpPathsStatus(statuses)
	for _, want := range []string{"162.159.192.1:2408", "188.114.96.1:2408", "188.114.97.1:2408", "188.114.98.1:2408", "16ms/30s", "sem resposta"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
}

func TestSelectPathAvoidsPrimaryWhileSwitching(t *testing.T) {
	e := &Engine{}
	p := &udpPath{}
	p.lastRx.Store(time.Now().UnixNano())
	e.paths[0] = p
	e.primaryHold.Store(true)
	for port := uint16(1); port <= 50; port++ {
		if got := e.selectPath(portKey{proto: 17, port: port}); got != 1 {
			t.Fatalf("port %d during switch uses path %d, want extra path 1", port, got)
		}
	}
	e.primaryHold.Store(false)
	seen := map[uint8]bool{}
	for port := uint16(1); port <= 50; port++ {
		seen[e.selectPath(portKey{proto: 17, port: port})] = true
	}
	if !seen[0] || !seen[1] {
		t.Fatalf("after switch both paths should be used, got %v", seen)
	}
}
