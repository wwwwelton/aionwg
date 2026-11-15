package app

// Configs for the official WireGuard client (no per-process routing there,
// only AllowedIPs): "sistema inteiro" without LAN, and "só jogo" by IP range.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// GameAllowed keeps the tunnel subnet plus only the WFP app server addresses
// AionWG actually saw, as /32 each.
func GameAllowed(c *WGConf, observed []netip.Addr, endpoints []netip.Addr) []netip.Prefix {
	out := tunnelSubnets(c)
	for _, a := range observed {
		if !a.Is4() || c.Bypass(a) {
			continue
		}
		out = append(out, netip.PrefixFrom(a, 32))
	}
	var ex []netip.Prefix
	for _, e := range endpoints {
		if e.Is4() {
			ex = append(ex, netip.PrefixFrom(e, 32))
		}
	}
	return mergeSorted(excludePrefixes(out, ex))
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
// The computed allowed list replaces AllowedIPs of the first [Peer] only:
// the same prefixes on two peers make WireGuard hand the route to the last
// one, so other peers keep the AllowedIPs they were configured with.
func RenderOfficial(raw, title string, allowed []netip.Prefix, keepDNS bool) string {
	var ss []string
	for _, p := range allowed {
		ss = append(ss, p.String())
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Gerado pelo AionWG — %s\n", title)
	section := ""
	peers := 0
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(strings.Trim(t, "[] "))
			if section == "peer" {
				peers++
			}
		}
		k, _, _ := strings.Cut(t, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if section == "interface" && k == "dns" && !keepDNS {
			continue
		}
		if section == "peer" && k == "allowedips" && peers == 1 {
			b.WriteString("AllowedIPs = " + strings.Join(ss, ", ") + "\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}
