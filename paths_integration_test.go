package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Four independent WireGuard servers simulate four distinct WARP edges. They
// share the same server and client keys, but each maintains its own sessions.
func TestFourUDPPathsCarryBidirectionalTraffic(t *testing.T) {
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientIP := netip.MustParseAddr("10.9.0.2")
	serverIP := netip.MustParseAddr("10.9.0.1")
	conf := &WGConf{PrivateKey: clientKey.Bytes(), MTU: 1420, Peers: []PeerConf{{
		PublicKey:  serverKey.PublicKey().Bytes(),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}}}
	var paths [4]*udpPath
	responses := make(chan int, len(paths))
	endpoints := make(map[netip.AddrPort]bool)
	for i := range paths {
		serverTun := newSplitTun(1420)
		serverTun.onInbound = func(pkt []byte) {
			info, ok := parsePacket(pkt)
			if !ok || (info.proto != protoICMP && info.proto != protoUDP) {
				return
			}
			reply := append([]byte(nil), pkt[:pktLen(pkt, &info)]...)
			src, dst := info.src, info.dst
			setSrc(reply, &info, dst)
			setDst(reply, &info, src)
			if info.proto == protoICMP {
				reply[info.l4] = 0
			} else {
				binary.BigEndian.PutUint16(reply[info.l4:], info.dstPort)
				binary.BigEndian.PutUint16(reply[info.l4+2:], info.srcPort)
			}
			fixChecksums(reply, &info)
			serverTun.inject(reply)
		}
		server := device.NewDevice(serverTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
		t.Cleanup(server.Close)
		must(t, server.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", serverKey.Bytes(), clientKey.PublicKey().Bytes())))
		must(t, server.Up())
		state, err := server.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		port := udpListenPort(state)
		if port == 0 {
			t.Fatal("server has no UDP port")
		}
		endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
		if endpoints[endpoint] {
			t.Fatalf("endpoint reused: %s", endpoint)
		}
		endpoints[endpoint] = true
		path, err := newUDPPath(conf, endpoint, uint16(0xa110+i), func(pkt []byte) {
			p, ok := parsePacket(pkt)
			if ok && p.proto == protoUDP && strings.HasPrefix(string(pkt[p.l4+8:]), "path-") {
				responses <- i
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		paths[i] = path
		t.Cleanup(path.close)
	}

	deadline := time.Now().Add(8 * time.Second)
	for {
		all := true
		for _, p := range paths {
			if !p.active(time.Now()) {
				all = false
				p.probe(clientIP, serverIP)
			}
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not all four endpoints completed a data-plane round trip")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, p := range paths {
		p.tun.inject(buildUDP4(clientIP, serverIP, uint16(40000+i), 50000, []byte(fmt.Sprintf("path-%d", i))))
	}
	got := map[int]bool{}
	for range paths {
		select {
		case i := <-responses:
			got[i] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of four paths returned UDP traffic: %v", len(got), got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("responses did not arrive on four paths: %v", got)
	}
}
