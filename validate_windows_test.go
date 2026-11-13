//go:build windows

package main

import (
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWg03JogoGemini(t *testing.T) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		appdata = `C:\Users\av4t\AppData\Roaming`
	}
	p := filepath.Join(appdata, "AionWG", "configs", "wg03-jogo-gemini.conf")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("config wg03-jogo-gemini.conf not found: %v", err)
	}
	c, err := ParseConfig(string(raw))
	if err != nil {
		t.Fatalf("failed to parse wg03-jogo-gemini.conf: %v", err)
	}

	if c.MTU != 1412 {
		t.Errorf("expected MTU 1412, got %d", c.MTU)
	}
	if len(c.Peers) == 0 {
		t.Fatal("no peers in wg03-jogo-gemini.conf")
	}
	peer := c.Peers[0]
	if peer.Keepalive <= 0 {
		t.Errorf("expected positive keepalive, got %d", peer.Keepalive)
	}

	// Validate routing coverage for game and services
	for _, ipStr := range []string{"193.202.112.161", "216.107.254.84", "8.233.158.151", "20.226.177.229"} {
		a := netip.MustParseAddr(ipStr)
		if !c.Allowed(a) {
			t.Errorf("destination %s not covered by AllowedIPs", a)
		}
	}
	t.Logf("Config wg03-jogo-gemini.conf: MTU=%d Keepalive=%ds Peers=%d AllowedIPs=%v",
		c.MTU, peer.Keepalive, len(c.Peers), peer.AllowedIPs)

	// Test DNS servers specified in config
	for _, dns := range c.DNS {
		n, err := dnsUDP(dns.String(), "api.steampowered.com")
		if err != nil {
			t.Errorf("DNS %s failed: %v", dns, err)
		} else {
			t.Logf("DNS %s (specified in config) responded with %d answers", dns, n)
		}
	}

	// Stress test UDP send to endpoint at MTU payload size (1412 - 28 = 1384 bytes)
	ep, err := ResolveEndpoint(peer.Endpoint)
	if err != nil {
		t.Fatalf("failed to resolve endpoint %s: %v", peer.Endpoint, err)
	}
	t.Logf("Testing UDP send to resolved peer endpoint %s at MTU 1412 (payload 1384B)...", ep)
	conn, err := net.Dial("udp", ep.String())
	if err != nil {
		t.Fatalf("dial UDP endpoint failed: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, c.MTU-28)
	const count = 50
	var rtts []time.Duration
	for i := range count {
		t0 := time.Now()
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("UDP write %d failed: %v", i, err)
		}
		rtts = append(rtts, time.Since(t0))
		time.Sleep(5 * time.Millisecond)
	}
	var sum time.Duration
	minRTT, maxRTT := time.Hour, time.Duration(0)
	for _, r := range rtts {
		sum += r
		if r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
	}
	avgRTT := sum / time.Duration(len(rtts))
	var diffSum float64
	for i := 1; i < len(rtts); i++ {
		diffSum += math.Abs(float64(rtts[i] - rtts[i-1]))
	}
	jitter := time.Duration(diffSum / float64(len(rtts)-1))
	t.Logf("UDP send load (50 packets @ MTU %dB): min=%v avg=%v max=%v local_jitter=%v (0 packet errors)",
		c.MTU, minRTT, avgRTT, maxRTT, jitter)

	// ICMP round-trip latency, jitter and loss measurement via native pinger
	pinger, err := newIcmpPinger()
	if err != nil {
		t.Logf("icmpPinger unavailable: %v", err)
		return
	}
	defer pinger.close()

	measureICMP := func(name string, target netip.Addr) {
		const pingCount = 30
		var pingRTTs []time.Duration
		for range pingCount {
			rtt, code := pinger.ping(target, 2*time.Second)
			if code == 0 {
				pingRTTs = append(pingRTTs, rtt)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if len(pingRTTs) > 0 {
			var pSum time.Duration
			pMin, pMax := time.Hour, time.Duration(0)
			for _, r := range pingRTTs {
				pSum += r
				if r < pMin {
					pMin = r
				}
				if r > pMax {
					pMax = r
				}
			}
			pAvg := pSum / time.Duration(len(pingRTTs))
			var pDiff float64
			for i := 1; i < len(pingRTTs); i++ {
				pDiff += math.Abs(float64(pingRTTs[i] - pingRTTs[i-1]))
			}
			pJitter := time.Duration(pDiff / float64(len(pingRTTs)-1))
			loss := float64(pingCount-len(pingRTTs)) / float64(pingCount) * 100
			t.Logf("ICMP %s (%s, %d probes): min=%v avg=%v max=%v jitter=%v loss=%.1f%%",
				name, target, pingCount, pMin, pAvg, pMax, pJitter, loss)
		}
	}

	measureICMP("WireGuard peer endpoint", ep.Addr())
	measureICMP("AION 2 game server", netip.MustParseAddr("193.202.112.161"))
}
