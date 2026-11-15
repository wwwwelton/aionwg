package app

import (
	"net/netip"
	"strings"
	"testing"
)

// Forced UDP copies need the device to accept destinations outside the
// profile's AllowedIPs; software routing still uses conf.Allowed.
func TestUAPIDeviceAcceptsAnyDestinationButConfStaysNarrow(t *testing.T) {
	c := &WGConf{PrivateKey: make([]byte, 32), Peers: []PeerConf{{
		PublicKey:  make([]byte, 32),
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}}}
	u := c.UAPI([]netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:51820")})
	for _, w := range []string{"allowed_ip=10.0.0.0/8", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0"} {
		if !strings.Contains(u, w) {
			t.Fatalf("missing %q in %s", w, u)
		}
	}
	if c.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("conf.Allowed must stay narrow")
	}
}
