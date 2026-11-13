package conn

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsUDPTuning(t *testing.T) {
	for _, family := range []int32{windows.AF_INET, windows.AF_INET6} {
		if _, ok := NewWinRingBind().(*WinRingBind); !ok {
			t.Skip("registered I/O unavailable")
		}
		var b afWinRingBind
		var sa windows.Sockaddr = &windows.SockaddrInet4{}
		if family == windows.AF_INET6 {
			sa = &windows.SockaddrInet6{}
		}
		if _, err := b.Open(family, sa); err != nil {
			t.Fatal(err)
		}
		for _, option := range []int{windows.SO_RCVBUF, windows.SO_SNDBUF} {
			got, err := windows.GetsockoptInt(b.sock, windows.SOL_SOCKET, option)
			if err != nil || got != 4<<20 {
				t.Fatalf("family %d buffer %d=%d err=%v", family, option, got, err)
			}
		}
		b.CloseAndZero()
	}
}

func TestWindowsDSCP(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("DSCP requires elevated Windows test process")
	}
	for _, addr := range []string{"192.0.2.1:51820", os.Getenv("AIONWG_TEST_IPV6_ENDPOINT")} {
		if _, ok := NewWinRingBind().(*WinRingBind); !ok {
			t.Skip("registered I/O unavailable")
		}
		t.Run(addr, func(t *testing.T) {
			if addr == "" {
				t.Skip("set AIONWG_TEST_IPV6_ENDPOINT to a reachable IPv6 address:port")
			}
			family := int32(windows.AF_INET)
			var sa windows.Sockaddr = &windows.SockaddrInet4{}
			if netip.MustParseAddrPort(addr).Addr().Is6() {
				family = windows.AF_INET6
				sa = &windows.SockaddrInet6{}
			}
			var b afWinRingBind
			if _, err := b.Open(family, sa); err != nil {
				t.Fatal(err)
			}
			defer b.CloseAndZero()
			endpoint, err := new(WinRingBind).ParseEndpoint(addr)
			if err != nil {
				t.Fatal(err)
			}
			ep := endpoint.(*WinRingEndpoint)
			if err := b.qos.mark(b.sock, ep); err != nil {
				t.Fatal(err)
			}
			var priority struct{ ConformantDSCP, NonConformantDSCP, ConformantL2, NonConformantL2 uint32 }
			size := uint32(unsafe.Sizeof(priority))
			query := qwave.NewProc("QOSQueryFlow")
			if ok, _, err := query.Call(uintptr(b.qos.handle), uintptr(b.qos.flows[*ep]), 1, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&priority)), 0, 0); ok == 0 {
				t.Fatal(err)
			}
			if priority.ConformantDSCP != 46 {
				t.Fatalf("DSCP=%d", priority.ConformantDSCP)
			}
		})
	}
}

func TestWindowsUDPResetReadContinues(t *testing.T) {
	// The fallback socket must survive an ICMP response from a closed local port.
	lc := listenConfig()
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	closed, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := closed.LocalAddr()
	closed.Close()
	if _, err := pc.WriteTo([]byte("probe"), dst); err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.WriteTo([]byte("alive"), pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	var buf [16]byte
	n, _, err := pc.ReadFrom(buf[:])
	if err != nil || string(buf[:n]) != "alive" {
		t.Fatalf("read=%q err=%v", buf[:n], err)
	}
}
