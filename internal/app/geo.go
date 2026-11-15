package app

// Where the tunnel exits. Cloudflare's resolver answers two CHAOS TXT names
// about the connection it sees: whoami.cloudflare (the public exit IP) and
// id.server (the data centre, e.g. "cwb01"). They are asked through the tunnel
// with plain UDP packets (no TCP stack needed). The exit IP is then looked up
// once for city/country.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ExitInfo describes the tunnel exit seen through Endpoint.
type ExitInfo struct {
	IP, Colo, City, Country string
	Endpoint                netip.AddrPort
	At                      time.Time
}

// buildChaosTXT is a DNS query for name, type TXT, class CH.
func buildChaosTXT(name string, id uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 16, 0, 3) // TXT, CH
}

// parseChaosTXT returns the first TXT string of the response to query id.
func parseChaosTXT(b []byte, id uint16) (string, bool) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[3]&0x0f != 0 || binary.BigEndian.Uint16(b[6:]) == 0 {
		return "", false
	}
	skipName := func(i int) int { // -1 when malformed
		for i >= 0 && i < len(b) {
			switch l := int(b[i]); {
			case l == 0:
				return i + 1
			case l&0xC0 == 0xC0:
				return i + 2
			default:
				i += l + 1
			}
		}
		return -1
	}
	i := skipName(12)
	if i < 0 {
		return "", false
	}
	if i = skipName(i + 4); i < 0 || i+10 > len(b) { // QTYPE+QCLASS, then the answer's name
		return "", false
	}
	rdlen := int(binary.BigEndian.Uint16(b[i+8:]))
	r := b[i+10:]
	if rdlen < 1 || rdlen > len(r) {
		return "", false
	}
	r = r[:rdlen]
	if n := int(r[0]); n+1 <= len(r) {
		return string(r[1 : 1+n]), true
	}
	return "", false
}

// buildUDP4 builds an IPv4/UDP packet with valid checksums.
func buildUDP4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, protoUDP
	s, d := src.As4(), dst.As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	if p, ok := parsePacket(b); ok {
		fixChecksums(b, &p)
	}
	return b
}

// geoIPURL is a variable so tests can point it at a local server.
var geoIPURL = "http://ip-api.com/json/%s?fields=status,country,countryCode,city"

// geoIPLookup returns the city and country code of a public IP.
func geoIPLookup(client *http.Client, ip string) (city, country string, err error) {
	resp, err := client.Get(fmt.Sprintf(geoIPURL, ip))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var r struct {
		Status, City, CountryCode string
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", "", err
	}
	if r.Status != "success" {
		return "", "", fmt.Errorf("sem geolocalização para %s", ip)
	}
	return r.City, r.CountryCode, nil
}

// warpSeeds are the documented WARP WireGuard /24 blocks (host .1) outside the
// neighbourhood of cur; they are returned only when cur is itself in one of
// the two WARP /22s, so other VPNs never get Cloudflare addresses injected.
func warpSeeds(cur netip.Addr) []netip.Addr {
	a, b := netip.MustParsePrefix("162.159.192.0/22"), netip.MustParsePrefix("188.114.96.0/22")
	if !a.Contains(cur) && !b.Contains(cur) {
		return nil
	}
	var out []netip.Addr
	for _, base := range [][4]byte{{162, 159, 192, 1}, {188, 114, 96, 1}} {
		for n := byte(0); n < 4; n++ {
			s := base
			s[2] += n
			if addr := netip.AddrFrom4(s); addr != cur {
				out = append(out, addr)
			}
		}
	}
	return out
}
