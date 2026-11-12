package main

// Configs for the official WireGuard client (no per-process routing there,
// only AllowedIPs): "sistema inteiro" without LAN, and "só jogo" by IP range.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// AION 2 / NCSOFT (AS142005 via ipverse/asn-ip + bgp.he.net, plus servers
// seen in use) and Valve/Steam (AS32590).
var ncsoftRanges = []string{
	"193.202.112.0/24", // servidor do AION 2 informado pelo usuário (193.202.112.161)
	"210.61.114.0/24",  // NCSOFT, faltavam na lista ipverse (bgp.he.net)
	"210.242.83.0/24",
	"210.242.123.0/24",
	"210.242.186.0/24",
	"64.25.32.0/21",
	"64.25.41.0/24",
	"85.113.86.0/23",
	"103.164.130.0/23",
	"193.149.158.0/23",
	"193.149.166.0/23",
	"206.127.144.0/22",
	"206.127.148.0/23",
	"206.127.152.0/22",
	"206.127.156.0/23",
	"209.35.96.0/23",
	"209.35.114.0/23",
	"209.35.156.0/23",
	"209.35.188.0/23",
	"210.61.3.0/24",
	"210.61.107.0/24",
	"210.242.118.0/24",
	"216.107.240.0/20",
}

var valveRanges = []string{
	"45.121.184.0/24",
	"103.10.124.0/23",
	"103.28.54.0/24",
	"146.66.152.0/24",
	"146.66.155.0/24",
	"155.133.224.0/21",
	"155.133.236.0/22",
	"155.133.240.0/23",
	"155.133.244.0/24",
	"155.133.246.0/24",
	"155.133.248.0/22",
	"155.133.252.0/24",
	"155.133.254.0/23",
	"162.254.192.0/21",
	"185.25.180.0/24",
	"185.25.182.0/23",
	"192.69.96.0/22",
	"205.196.6.0/24",
	"208.64.200.0/22",
	"208.78.164.0/22",
}

// excludePrefixes returns base minus ex, as a minimal list of prefixes.
func excludePrefixes(base []netip.Prefix, ex []netip.Prefix) []netip.Prefix {
	cur := base
	for _, e := range ex {
		var next []netip.Prefix
		for _, p := range cur {
			next = append(next, subtract(p, e)...)
		}
		cur = next
	}
	return cur
}

func subtract(p, e netip.Prefix) []netip.Prefix {
	if !p.Overlaps(e) {
		return []netip.Prefix{p}
	}
	if e.Bits() <= p.Bits() { // e covers p
		return nil
	}
	// split p in halves and recurse
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hi := netip.PrefixFrom(lastAddr(lo).Next(), p.Bits()+1)
	return append(subtract(lo, e), subtract(hi, e)...)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// tunnelSubnets returns the VPN-side subnets to keep in AllowedIPs
// (a /32 address becomes its /24, where the server usually lives).
func tunnelSubnets(c *WGConf) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range c.Addresses {
		if !a.Addr().Is4() {
			continue
		}
		bits := a.Bits()
		if bits > 24 {
			bits = 24
		}
		out = append(out, netip.PrefixFrom(a.Addr(), bits).Masked())
	}
	return out
}

func mustPrefixes(ss []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// FullTunnelAllowed is 0.0.0.0/0 minus LAN/private/multicast and the VPN
// endpoint itself, plus the tunnel subnet.
func FullTunnelAllowed(c *WGConf, endpoints []netip.Addr) []netip.Prefix {
	ex := mustPrefixes([]string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	})
	for _, e := range endpoints {
		if e.Is4() {
			ex = append(ex, netip.PrefixFrom(e, 32))
		}
	}
	out := excludePrefixes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, ex)
	// ::/0 keeps IPv6 from leaking around the tunnel; without an IPv6
	// address on the tunnel Windows fails IPv6 at once and apps use IPv4.
	out = append(out, netip.MustParsePrefix("::/0"))
	return mergeSorted(append(out, tunnelSubnets(c)...))
}

// GameAllowed is NCSOFT + Valve ranges, the tunnel subnet and any game/Steam
// server addresses AionWG actually saw (as /24).
func GameAllowed(c *WGConf, observed []netip.Addr, endpoints []netip.Addr) []netip.Prefix {
	out := mustPrefixes(ncsoftRanges)
	out = append(out, mustPrefixes(valveRanges)...)
	out = append(out, tunnelSubnets(c)...)
	for _, a := range observed {
		if !a.Is4() || c.Bypass(a) {
			continue
		}
		out = append(out, netip.PrefixFrom(a, 24).Masked())
	}
	var ex []netip.Prefix
	for _, e := range endpoints {
		if e.Is4() {
			ex = append(ex, netip.PrefixFrom(e, 32))
		}
	}
	return mergeSorted(excludePrefixes(out, ex))
}

// mergeSorted drops duplicates and prefixes contained in others.
func mergeSorted(ps []netip.Prefix) []netip.Prefix {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range ps {
		if len(out) > 0 {
			last := out[len(out)-1]
			if last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// RenderOfficial rewrites a wg-quick config for the official client.
func RenderOfficial(raw, title string, allowed []netip.Prefix, keepDNS bool) string {
	var ss []string
	for _, p := range allowed {
		ss = append(ss, p.String())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Gerado pelo AionWG — %s\n", title)
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(strings.Trim(t, "[] "))
		}
		k, _, _ := strings.Cut(t, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if section == "interface" && k == "dns" && !keepDNS {
			continue
		}
		if section == "peer" && k == "allowedips" {
			b.WriteString("AllowedIPs = " + strings.Join(ss, ", ") + "\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
