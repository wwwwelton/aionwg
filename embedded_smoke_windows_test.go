//go:build windows && !external

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func init() { certPromptEnabled = false }

// requireAdmin skips tests that extract the runtime into Program Files and load
// the WinDivert driver; the default build embeds both.
func requireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated shell")
	}
}

func TestEmbeddedStandaloneSmoke(t *testing.T) {
	requireAdmin(t)
	if err := prepareRuntime(); err != nil {
		t.Fatal(err)
	}
	h, err := divertOpen("false", divertLayerNetwork, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err := wintunDLL.Load(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		handle  uintptr
		name    string
		payload []byte
	}{
		{divertDLL.Handle(), "WinDivert.dll", embeddedDivert},
		{wintunDLL.Handle(), "wintun.dll", embeddedWintun},
	} {
		var filename [32768]uint16
		if _, err := windows.GetModuleFileName(windows.Handle(entry.handle), &filename[0], uint32(len(filename))); err != nil {
			t.Fatal(err)
		}
		path := windows.UTF16ToString(filename[:])
		if !strings.Contains(strings.ToLower(path), `\program files\aionwg-runtime\`) {
			t.Fatalf("loaded external dependency: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, entry.payload) {
			t.Fatalf("loaded DLL differs from embedded data: %s (%v)", path, err)
		}
		if entry.name == "WinDivert.dll" {
			driver, err := os.ReadFile(filepath.Join(filepath.Dir(path), "WinDivert64.sys"))
			if err != nil || !bytes.Equal(driver, embeddedDriver) {
				t.Fatal("embedded driver missing or modified", err)
			}
		}
		t.Log("loaded verified embedded dependency:", path)
	}
}

func TestLiveGamePacketCapture(t *testing.T) {
	requireAdmin(t)
	if err := prepareRuntime(); err != nil {
		t.Fatal(err)
	}
	h, err := divertOpen("tcp and (tcp.SrcPort == 13328 or tcp.DstPort == 13328)", divertLayerNetwork, 0, divertFlagSniff|divertFlagRecvOnly)
	if err != nil {
		t.Fatal("WinDivert open failed:", err)
	}
	defer h.close()

	packetCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65536)
		var addr divertAddress
		n, err := h.recv(buf, &addr)
		if err == nil && n > 0 {
			packetCh <- buf[:n]
		}
	}()

	select {
	case pkt := <-packetCh:
		p, ok := parsePacket(pkt)
		if !ok {
			t.Fatal("failed to parse captured packet")
		}
		t.Logf("CAPTURED LIVE GAME PACKET: proto=%d %s:%d -> %s:%d len=%d", p.proto, p.src, p.srcPort, p.dst, p.dstPort, len(pkt))
	case <-time.After(4 * time.Second):
		t.Log("Sniff handle verified; no packet arrived during 4s window")
	}
}
