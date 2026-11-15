//go:build windows

package app

import (
	"net/netip"
	"testing"
	"unsafe"
)

// The portable decoder reads a raw WINDIVERT_ADDRESS with hard-coded offsets.
// Pin them against the real Go struct (which already drives the NETWORK layer
// in production) so a layout mistake cannot pass on both sides of a test.
func TestSocketOffsetsMatchDivertAddress(t *testing.T) {
	var a divertAddress
	if got := unsafe.Sizeof(a); got != wdAddrSize {
		t.Fatalf("sizeof(divertAddress) = %d, decoder assumes %d", got, wdAddrSize)
	}
	// The SOCKET union starts where Network.IfIdx starts.
	if got := unsafe.Offsetof(a.IfIdx); got != wdAddrUnion {
		t.Fatalf("union offset = %d, decoder assumes %d", got, wdAddrUnion)
	}
	// Timestamp(8) then the bit-field word: Layer is byte 8, Event is byte 9.
	if got := unsafe.Offsetof(a.bits); got != 8 {
		t.Fatalf("bits offset = %d, decoder reads Layer/Event at 8/9", got)
	}
}

func TestCaptureFilterCompilesInWinDivert(t *testing.T) {
	if err := divertLoad(); err != nil {
		t.Skipf("WinDivert.dll unavailable: %v", err)
	}
	f := captureFilter([]netip.AddrPort{
		netip.MustParseAddrPort("56.124.121.11:51820"),
		netip.MustParseAddrPort("[2001:db8::1]:51820"),
	})
	if err := divertCheckFilter(f, divertLayerNetwork); err != nil {
		t.Fatalf("WinDivert rejected captureFilter: %v", err)
	}
}
