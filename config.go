package main

// Parser for wg-quick style .conf files and conversion to the wireguard-go UAPI.

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type PeerConf struct {
	PublicKey    []byte
	PresharedKey []byte
	Endpoint     string // host:port as written
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

type WGConf struct {
	PrivateKey []byte
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	Peers      []PeerConf
}

func decodeKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("chave inválida")
	}
	return k, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseConfig parses a wg-quick configuration.
func ParseConfig(text string) (*WGConf, error) {
	c := &WGConf{}
	section := ""
	var peer *PeerConf
	sc := bufio.NewScanner(strings.NewReader(text))
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, string(rune(0xFEFF))))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				c.Peers = append(c.Peers, PeerConf{Keepalive: 15})
				peer = &c.Peers[len(c.Peers)-1]
			}
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("linha %d: esperado chave = valor", ln)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		var err error
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				c.PrivateKey, err = decodeKey(v)
			case "address":
				for _, s := range splitList(v) {
					var p netip.Prefix
					if p, err = parsePrefix(s); err != nil {
						break
					}
					c.Addresses = append(c.Addresses, p)
				}
			case "mtu":
				c.MTU, err = strconv.Atoi(v)
			case "listenport":
				c.ListenPort, err = strconv.Atoi(v)
			case "dns":
				for _, d := range splitList(v) {
					if a, e := netip.ParseAddr(d); e == nil {
						c.DNS = append(c.DNS, a.Unmap())
					} // search domains are ignored
				}
			default:
				// PostUp, Table... are irrelevant here.
			}
		case "peer":
			switch k {
			case "publickey":
				peer.PublicKey, err = decodeKey(v)
			case "presharedkey":
				peer.PresharedKey, err = decodeKey(v)
			case "endpoint":
				if _, err = parseEndpointPort(v); err == nil {
					peer.Endpoint = v
				}
			case "allowedips":
				for _, s := range splitList(v) {
					var p netip.Prefix
					if p, err = parsePrefix(s); err != nil {
						break
					}
					peer.AllowedIPs = append(peer.AllowedIPs, p.Masked())
				}
			case "persistentkeepalive":
				peer.Keepalive = 0
				if v != "off" {
					peer.Keepalive, err = strconv.Atoi(v)
				}
			}
		default:
			return nil, fmt.Errorf("linha %d: fora de [Interface]/[Peer]", ln)
		}
		if err != nil {
			return nil, fmt.Errorf("linha %d (%s): %v", ln, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		// bufio.Scanner stops at lines over 64 KiB; without this the rest of
		// the file (including later peers) would be silently ignored.
		return nil, fmt.Errorf("linha %d: %v", ln+1, err)
	}
	if c.PrivateKey == nil {
		return nil, fmt.Errorf("PrivateKey ausente em [Interface]")
	}
	if len(c.Addresses) == 0 {
		return nil, fmt.Errorf("Address ausente em [Interface]")
	}
	if len(c.Peers) == 0 {
		return nil, fmt.Errorf("nenhum [Peer] encontrado")
	}
	for i, p := range c.Peers {
		if p.PublicKey == nil {
			return nil, fmt.Errorf("peer %d sem PublicKey", i+1)
		}
		if p.Endpoint == "" {
			return nil, fmt.Errorf("peer %d sem Endpoint", i+1)
		}
	}
	if c.MTU == 0 {
		c.MTU = 1420
	}
	return c, nil
}

// Addr returns the tunnel address for the given family.
func (c *WGConf) Addr(v6 bool) (netip.Addr, bool) {
	for _, p := range c.Addresses {
		if p.Addr().Is6() == v6 {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

// Allowed reports whether dst is routed through any peer.
func (c *WGConf) Allowed(dst netip.Addr) bool {
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Contains(dst) {
				return true
			}
		}
	}
	return false
}

// parseEndpointPort splits host:port and checks the port is 1-65535.
// It does not resolve DNS, so it is safe to call while parsing a file.
func parseEndpointPort(ep string) (int, error) {
	_, port, err := net.SplitHostPort(ep)
	if err != nil {
		return 0, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	if pn < 1 || pn > 65535 {
		return 0, fmt.Errorf("porta %d fora de 1-65535", pn)
	}
	return pn, nil
}

// ResolveEndpoint resolves host:port into a UDP address (IPv4 preferred).
func ResolveEndpoint(ep string) (netip.AddrPort, error) {
	host, _, err := net.SplitHostPort(ep)
	if err != nil {
		return netip.AddrPort{}, err
	}
	pn, err := parseEndpointPort(ep)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a.Unmap(), uint16(pn)), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("não resolveu %s: %v", host, err)
	}
	best := ips[0]
	for _, ip := range ips {
		if ip.To4() != nil {
			best = ip
			break
		}
	}
	a, _ := netip.AddrFromSlice(best)
	return netip.AddrPortFrom(a.Unmap(), uint16(pn)), nil
}

// UAPI renders the configuration for device.IpcSet. Endpoints must be pre-resolved.
func (c *WGConf) UAPI(endpoints []netip.AddrPort) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKey))
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for i, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey))
		if p.PresharedKey != nil {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(p.PresharedKey))
		}
		fmt.Fprintf(&b, "endpoint=%s\n", endpoints[i].String())
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
		}
		// Software routing (Engine.capture) decides what enters the tunnel; the
		// device must accept any destination so forced UDP copies are not dropped.
		if len(c.Peers) == 1 {
			b.WriteString("allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n")
		}
	}
	return b.String()
}
