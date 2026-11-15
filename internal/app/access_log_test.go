package app

import (
	"net/netip"
	"strings"
	"testing"
)

func TestAccessLogGroupsRemotesPerProgram(t *testing.T) {
	var a accessLog
	a.add("aion2.exe", netip.MustParseAddrPort("104.28.196.100:7777"))
	a.add("aion2.exe", netip.MustParseAddrPort("104.28.196.100:7777"))
	a.add("aion2.exe", netip.MustParseAddrPort("1.1.1.1:443"))
	a.add("chrome.exe", netip.MustParseAddrPort("8.8.8.8:53"))

	got := a.take()
	want := []string{
		"aion2.exe -> 1.1.1.1:443, 104.28.196.100:7777",
		"chrome.exe -> 8.8.8.8:53",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("take() = %q, want %q", got, want)
	}
	if left := a.take(); len(left) != 0 {
		t.Fatalf("second take() = %q, want empty (state must reset)", left)
	}
}

func TestAccessLogCapsRemotesPerProgram(t *testing.T) {
	var a accessLog
	for i := 0; i < accessMaxPerProg+10; i++ {
		a.add("scanner.exe", netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 80))
	}
	line := a.take()[0]
	if n := strings.Count(line, ","); n != accessMaxPerProg-1 {
		t.Fatalf("listed %d remotes, want %d", n+1, accessMaxPerProg)
	}
}
