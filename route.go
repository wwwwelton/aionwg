package main

// Routing decisions for the "sistema inteiro" (full tunnel) mode.

import (
	"fmt"
	"net/netip"
)

var localRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Bypass reports whether dst must stay on the local network (router, printer,
// LAN games…) in full-tunnel mode. Private addresses still go through the
// tunnel when they belong to the tunnel subnet or to a specific AllowedIPs
// route (e.g. 10.10.0.0/16 on the VPN side).
func (c *WGConf) Bypass(dst netip.Addr) bool {
	if dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	local := false
	for _, p := range localRanges {
		if p.Contains(dst) {
			local = true
			break
		}
	}
	if !local {
		return false
	}
	for _, a := range c.Addresses {
		if a.Masked().Contains(dst) {
			return false
		}
	}
	for _, peer := range c.Peers {
		for _, a := range peer.AllowedIPs {
			if a.Bits() >= 8 && a.Contains(dst) {
				return false
			}
		}
	}
	return true
}

// DNSFor returns the config's DNS server for the family, if any.
func (c *WGConf) DNSFor(v6 bool) (netip.Addr, bool) {
	for _, d := range c.DNS {
		if d.Is6() == v6 {
			return d, true
		}
	}
	return netip.Addr{}, false
}

const baseCaptureFilter = "outbound and not loopback and (tcp or udp)"

// captureFilter builds the WinDivert NETWORK filter excluding the VPN
// endpoints' own UDP packets. In WinDivert's grammar "not" only negates a
// single field test (TEST0), never a parenthesised compound expression, and a
// test on an absent header (e.g. udp.DstPort != N on TCP) evaluates to false,
// so compound negation uses the conditional form "(cond? false: true)".
func captureFilter(endpoints []netip.AddrPort) string {
	filter := baseCaptureFilter
	for _, ep := range endpoints {
		ipf := "ip.DstAddr"
		if ep.Addr().Is6() {
			ipf = "ipv6.DstAddr"
		}
		filter += fmt.Sprintf(" and ((udp.DstPort == %d and %s == %s)? false: true)", ep.Port(), ipf, ep.Addr())
	}
	return filter
}
