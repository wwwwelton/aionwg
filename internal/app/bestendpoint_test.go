package app

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func table(m map[string]time.Duration) func(netip.Addr) (time.Duration, bool) {
	return func(a netip.Addr) (time.Duration, bool) {
		d, ok := m[a.String()]
		return d, ok
	}
}

func TestRankEndpointsBestFirstWithMarginAndLimit(t *testing.T) {
	ms := time.Millisecond
	cur := netip.MustParseAddrPort("203.0.113.1:2408")
	cands := []netip.Addr{cur.Addr()}
	rtts := map[string]time.Duration{"203.0.113.1": 25 * ms}
	for i, name := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"} {
		cands = append(cands, netip.MustParseAddr(name))
		rtts[name] = time.Duration(20-i*2) * ms // 20,18,16,14,12
	}
	cands = append(cands, netip.MustParseAddr("198.51.100.9")) // does not answer
	rtts["198.51.100.6"] = 24 * ms                             // inside the margin, never listed
	cands = append(cands, netip.MustParseAddr("198.51.100.6"))

	curRTT, ranked := rankEndpoints(cur, cands, table(rtts), table(rtts))
	if curRTT != 25*ms {
		t.Fatalf("curRTT %v", curRTT)
	}
	if len(ranked) != maxTrials || ranked[0].String() != "198.51.100.5:2408" || ranked[1].String() != "198.51.100.4:2408" {
		t.Fatalf("ranked %v", ranked)
	}
}

func TestRankEndpointsKeepsCurrentWhenSilentOrAlreadyBest(t *testing.T) {
	ms := time.Millisecond
	cur := netip.MustParseAddrPort("203.0.113.1:2408")
	cands := []netip.Addr{cur.Addr(), netip.MustParseAddr("198.51.100.1")}
	if rtt, r := rankEndpoints(cur, cands, table(map[string]time.Duration{"198.51.100.1": 5 * ms}), table(map[string]time.Duration{"198.51.100.1": 5 * ms})); rtt != 0 || r != nil {
		t.Fatalf("silent current must compare nothing: %v %v", rtt, r)
	}
	same := map[string]time.Duration{"203.0.113.1": 14 * ms, "198.51.100.1": 13 * ms}
	if rtt, r := rankEndpoints(cur, cands, table(same), table(same)); rtt != 14*ms || len(r) != 0 {
		t.Fatalf("within margin: %v %v", rtt, r)
	}
}

func TestEndpointCandidatesAreDerivedFromTheEndpoint(t *testing.T) {
	noDNS := func(string) ([]netip.Addr, error) { return nil, errors.New("no dns") }
	pub := netip.MustParseAddrPort("203.0.113.1:51820")
	c := endpointCandidates(pub, "203.0.113.1", noDNS)
	if len(c) != 4 || c[0] != pub.Addr() {
		t.Fatalf("public: current first + same host octet in the other 3 /24s of its /22, got %v", c)
	}
	for _, a := range c[1:] {
		b := a.As4()
		if b[0] != 203 || b[1] != 0 || b[2] < 112 || b[2] > 115 || b[3] != 1 || a == pub.Addr() {
			t.Fatalf("unexpected neighbour %v", a)
		}
	}
	for _, private := range []string{"192.168.1.1:51820", "10.0.0.1:51820", "172.16.0.1:51820", "100.64.0.1:51820", "127.0.0.1:51820"} {
		if c := endpointCandidates(netip.MustParseAddrPort(private), "x", noDNS); len(c) != 1 {
			t.Fatalf("%s must not be swept: %d candidates", private, len(c))
		}
	}
	dns := func(string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::1"), pub.Addr()}, nil
	}
	c = endpointCandidates(netip.MustParseAddrPort("192.168.1.1:51820"), "vpn.example.net", dns)
	if len(c) != 3 || c[1].String() != "192.0.2.9" || c[2].String() != "203.0.113.1" {
		t.Fatalf("DNS IPv4 answers on a private endpoint: %v", c)
	}
	lit := func(string) ([]netip.Addr, error) { t.Fatal("literal IP must not be resolved"); return nil, nil }
	endpointCandidates(pub, "203.0.113.1", lit)
}

func TestHandshakenPeersOnlyListsPeersWithAHandshake(t *testing.T) {
	dump := "private_key=x\nlisten_port=1\npublic_key=aa\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n" +
		"public_key=bb\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n"
	got := handshakenPeers(dump)
	if got["aa"] || !got["bb"] || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
