package main

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Two wireguard-go devices on loopback, each backed by splitTun.
// A sends an ICMP echo through the tunnel; B answers; A must get the reply.
func TestSplitTunThroughWireGuard(t *testing.T) {
	kA, _ := base64.StdEncoding.DecodeString("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
	kB, _ := base64.StdEncoding.DecodeString("WAmgVYXkbT2bCtdcDwolI88/iVi/aV3/PHcUBTQSYmo=")
	pubA, pubB := pub(kA), pub(kB)

	tA, tB := newSplitTun(1420), newSplitTun(1420)
	tB.onInbound = func(b []byte) {
		p, ok := parsePacket(b)
		if !ok || p.proto != protoICMP {
			return
		}
		out := append([]byte(nil), b[:pktLen(b, &p)]...)
		src, dst := p.src, p.dst
		setSrc(out, &p, dst)
		setDst(out, &p, src)
		out[p.l4] = 0 // echo reply
		fixChecksums(out, &p)
		tB.inject(out)
	}
	got := make(chan uint16, 1)
	tA.onInbound = func(b []byte) {
		p, ok := parsePacket(b)
		if !ok {
			return
		}
		if _, seq, ok := parseICMPEchoReply(b, &p); ok {
			got <- seq
		}
	}
	log := device.NewLogger(device.LogLevelError, "")
	dA := device.NewDevice(tA, conn.NewDefaultBind(), log)
	dB := device.NewDevice(tB, conn.NewDefaultBind(), log)
	defer dA.Close()
	defer dB.Close()

	must(t, dB.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=51999\npublic_key=%x\nallowed_ip=10.9.0.2/32\n", kB, pubA)))
	must(t, dA.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nendpoint=127.0.0.1:51999\nallowed_ip=0.0.0.0/0\n", kA, pubB)))
	must(t, dB.Up())
	must(t, dA.Up())

	src, dst := netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("10.9.0.1")
	deadline := time.After(5 * time.Second)
	for seq := uint16(1); ; seq++ {
		tA.inject(buildICMPEcho(src, dst, 1, seq))
		select {
		case s := <-got:
			t.Logf("echo reply seq=%d", s)
			return
		case <-time.After(300 * time.Millisecond):
		case <-deadline:
			t.Fatal("no reply through tunnel")
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func pub(priv []byte) []byte {
	out, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return out
}

func TestSplitTunCloseEndsEvents(t *testing.T) {
	tun := newSplitTun(1420)
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case _, ok := <-tun.Events():
			if !ok {
				return
			}
		case <-time.After(time.Second):
			t.Fatal("event consumer remained blocked after Close")
		}
	}
}

func TestSplitTunDropsOversized(t *testing.T) {
	st := newSplitTun(1420)
	big := make([]byte, 3000)
	ok := make([]byte, 100)
	st.inject(big)
	st.inject(ok)
	bufs := [][]byte{make([]byte, 2016+16), make([]byte, 2016+16)}
	sizes := make([]int, 2)
	n, err := st.Read(bufs, sizes, 16)
	if err != nil || n != 1 || sizes[0] != 100 {
		t.Fatalf("n=%d sizes=%v err=%v", n, sizes, err)
	}
	if st.drops.Load() != 1 {
		t.Fatalf("drops=%d", st.drops.Load())
	}
}
