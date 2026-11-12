package main

import (
	"net/netip"
	"testing"
)

func TestBypass(t *testing.T) {
	c, err := ParseConfig(sampleConf + "\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:1\nAllowedIPs = 10.20.0.0/16\n")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"192.168.1.1":     true,  // router
		"8.8.8.8":         false, // internet
		"10.66.66.1":      false, // tunnel subnet
		"10.20.5.5":       false, // specific AllowedIPs
		"10.99.0.1":       true,  // other private
		"239.255.255.250": true,  // SSDP multicast
		"255.255.255.255": true,
		"fe80::1":         true,
		"2606:4700::1111": false,
		"fd42:42:42::1":   false, // tunnel v6 subnet
	}
	for a, want := range cases {
		if got := c.Bypass(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: got %v want %v", a, got, want)
		}
	}
	if d, ok := c.DNSFor(false); !ok || d.String() != "1.1.1.1" {
		t.Fatal("dns")
	}
}
