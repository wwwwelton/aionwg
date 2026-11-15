package app

// Traceroute-style view of the route in use: hops from the PC to the VPN
// endpoint (outside the tunnel) and from the endpoint to the game server
// (inside the tunnel), measured with TTL-limited ICMP echoes. The engine side
// lives in tunnel_windows.go; everything here is plain data and packet parsing.

import (
	"encoding/binary"
	"net/netip"
	"time"
)

const maxTraceHops = 20

// Hop is one router on the path; an invalid Addr means it did not answer.
type Hop struct {
	TTL  int
	Addr netip.Addr
	RTT  time.Duration
}

// RouteTrace is the latest measurement of the route in use.
type RouteTrace struct {
	At         time.Time
	Endpoint   netip.Addr // end of the direct segment
	Dest       netip.Addr // end of the tunnel segment
	DestIsGame bool       // Dest is the game server (false: only the tunnel gateway is known)
	Direct     []Hop      // PC -> endpoint, outside the tunnel
	Tunnel     []Hop      // inside the tunnel -> Dest
}

// trimHops keeps the hops up to the first one that is dst and drops trailing
// hops that did not answer.
func trimHops(hops []Hop, dst netip.Addr) []Hop {
	for i, h := range hops {
		if h.Addr == dst {
			return hops[:i+1]
		}
	}
	for len(hops) > 0 && !hops[len(hops)-1].Addr.IsValid() {
		hops = hops[:len(hops)-1]
	}
	return hops
}

// traceSeq packs a run counter and the TTL into an echo sequence number so
// late answers from an earlier run are told apart.
func traceSeq(run uint8, ttl int) uint16 { return uint16(run)<<8 | uint16(ttl&0xff) }

func traceUnseq(seq uint16) (run uint8, ttl int) { return uint8(seq >> 8), int(seq & 0xff) }

// parseTraceReply recognises the answer to one of our TTL-limited echo
// requests (identified by id): either an echo reply from the destination or an
// ICMP time-exceeded from a router that quotes our request. It returns who
// answered and the quoted sequence number.
func parseTraceReply(b []byte, p *pktInfo, id uint16) (from netip.Addr, seq uint16, ok bool) {
	if p.proto != protoICMP && p.proto != protoICMPv6 {
		return
	}
	n := pktLen(b, p)
	if n < p.l4+8 {
		return
	}
	t := b[p.l4:n]
	v6 := p.proto == protoICMPv6
	switch {
	case !v6 && t[0] == 0, v6 && t[0] == 129: // echo reply from the destination
		if binary.BigEndian.Uint16(t[4:]) == id {
			return p.src, binary.BigEndian.Uint16(t[6:]), true
		}
	case !v6 && t[0] == 11, v6 && t[0] == 3: // time exceeded: the request is quoted
		q := t[8:]
		var echo []byte
		if !v6 {
			if len(q) < 28 || q[0]>>4 != 4 {
				return
			}
			ihl := int(q[0]&0x0f) * 4
			if ihl < 20 || len(q) < ihl+8 || q[9] != protoICMP || q[ihl] != 8 {
				return
			}
			echo = q[ihl:]
		} else {
			if len(q) < 48 || q[0]>>4 != 6 || q[6] != protoICMPv6 || q[40] != 128 {
				return
			}
			echo = q[40:]
		}
		if binary.BigEndian.Uint16(echo[4:]) == id {
			return p.src, binary.BigEndian.Uint16(echo[6:]), true
		}
	}
	return
}
