package main

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// reply builds what a resolver returns for q: the question echoed plus one
// TXT answer whose name is a compression pointer.
func chaosReply(q []byte, txt string) []byte {
	r := append([]byte(nil), q...)
	r[2], r[3] = 0x81, 0x80
	binary.BigEndian.PutUint16(r[6:], 1)
	r = append(r, 0xC0, 0x0C, 0, 16, 0, 3, 0, 0, 0, 0, 0, byte(len(txt)+1), byte(len(txt)))
	return append(r, txt...)
}

func TestChaosTXTRoundTrip(t *testing.T) {
	q := buildChaosTXT("id.server", 0x1234)
	if got, ok := parseChaosTXT(chaosReply(q, "cwb01"), 0x1234); !ok || got != "cwb01" {
		t.Fatalf("got %q %v", got, ok)
	}
	if _, ok := parseChaosTXT(chaosReply(q, "cwb01"), 0x9999); ok {
		t.Fatal("a reply to another query id must be ignored")
	}
	short := chaosReply(q, "cwb01")
	for n := 0; n < len(short); n++ { // never panics on truncated input
		parseChaosTXT(short[:n], 0x1234)
	}
}

func TestBuildUDP4HasValidChecksums(t *testing.T) {
	b := buildUDP4(netip.MustParseAddr("172.16.0.2"), netip.MustParseAddr("1.1.1.1"), 54053, 53, buildChaosTXT("id.server", 1))
	p, ok := parsePacket(b)
	if !ok || p.proto != protoUDP || p.srcPort != 54053 || p.dstPort != 53 || pktLen(b, &p) != len(b) {
		t.Fatalf("bad packet %+v ok=%v", p, ok)
	}
	if csumFold(csumAdd(0, b[:20])) != 0 { // a correct IPv4 header sums to zero
		t.Fatal("IPv4 header checksum is wrong")
	}
}

func TestGeoIPLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","city":"Curitiba","countryCode":"BR"}`))
	}))
	defer srv.Close()
	defer func(u string) { geoIPURL = u }(geoIPURL)
	geoIPURL = srv.URL + "/%s"
	city, cc, err := geoIPLookup(&http.Client{Timeout: time.Second}, "203.0.113.9")
	if err != nil || city != "Curitiba" || cc != "BR" {
		t.Fatalf("%q %q %v", city, cc, err)
	}
}

func TestWarpSeedsOnlyForWarpRanges(t *testing.T) {
	if s := warpSeeds(netip.MustParseAddr("203.0.113.1")); s != nil {
		t.Fatalf("non-WARP endpoint got seeds: %v", s)
	}
	s := warpSeeds(netip.MustParseAddr("162.159.192.1"))
	if len(s) != 7 {
		t.Fatalf("seeds = %v", s)
	}
	for _, a := range s {
		if a == netip.MustParseAddr("162.159.192.1") {
			t.Fatal("the current endpoint must not be a seed")
		}
	}
}
