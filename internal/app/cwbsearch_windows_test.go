//go:build windows

package app

import (
	"net/netip"
	"testing"
	"time"
)

func TestCWBCandidatesOnlyProvenEndpoints(t *testing.T) {
	orig := netip.MustParseAddrPort("188.114.98.1:2408")
	learned := []netip.AddrPort{
		netip.MustParseAddrPort("162.159.192.1:2408"),
		orig,
	}
	got := cwbCandidates(learned, orig, 6)
	if len(got) != 2 || got[0] != orig || got[1] != netip.MustParseAddrPort("162.159.192.1:2408") {
		t.Fatalf("cwbCandidates = %v, want orig then proven endpoints only", got)
	}
}

func TestCWBCandidatesCapped(t *testing.T) {
	orig := netip.MustParseAddrPort("188.114.98.1:2408")
	var learned []netip.AddrPort
	for i := 1; i <= 9; i++ {
		learned = append(learned, netip.AddrPortFrom(netip.MustParseAddr("162.159.192.1"), uint16(2000+i)))
	}
	if got := cwbCandidates(learned, orig, 4); len(got) != 4 || got[0] != orig {
		t.Fatalf("cwbCandidates = %v, want 4 entries starting with orig", got)
	}
}

func TestCWBBestOnlyCuritiba(t *testing.T) {
	res := []cwbResult{
		{ep: netip.MustParseAddrPort("162.159.192.1:2408"), colo: "gru20", rtt: 2 * time.Millisecond},
		{ep: netip.MustParseAddrPort("188.114.98.1:2408"), colo: "cwb02", rtt: 9 * time.Millisecond},
		{ep: netip.MustParseAddrPort("188.114.99.33:2408"), colo: "cwb01", rtt: 7 * time.Millisecond},
	}
	best, ok := cwbBest(res)
	if !ok || best.ep != netip.MustParseAddrPort("188.114.99.33:2408") {
		t.Fatalf("cwbBest = %v %v, want cwb01 endpoint", best, ok)
	}
}

func TestCWBBestNoneWhenNoCuritiba(t *testing.T) {
	res := []cwbResult{{ep: netip.MustParseAddrPort("162.159.192.1:2408"), colo: "gru20", rtt: time.Millisecond}}
	if _, ok := cwbBest(res); ok {
		t.Fatal("cwbBest accepted a non-cwb endpoint")
	}
}
