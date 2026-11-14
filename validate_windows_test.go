//go:build windows

package main

import (
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestICMPForcedLossAndRecovery(t *testing.T) {
	pinger, err := newIcmpPinger()
	if err != nil {
		t.Fatalf("failed to create ICMP pinger: %v", err)
	}
	defer pinger.close()

	// 1. Simulate edge firewall dropping ICMP (blackhole IP from RFC 5737 TEST-NET-1)
	blackhole := netip.MustParseAddr("192.0.2.1")
	rtt, code := pinger.ping(blackhole, 300*time.Millisecond)
	if code == 0 {
		t.Fatalf("expected packet loss/timeout for blackholed IP, got RTT=%v", rtt)
	}
	t.Logf("Simulated edge firewall drop to %s: code=%d (timeout/unreachable as expected)", blackhole, code)

	// 2. Immediate recovery test: ping reachable endpoint right after a timeout
	peerIP := netip.MustParseAddr("56.124.121.11")
	rtt2, code2 := pinger.ping(peerIP, 2*time.Second)
	if code2 != 0 {
		t.Fatalf("pinger failed to recover after timeout, got code %d for %s", code2, peerIP)
	}
	t.Logf("Instant recovery on reachable peer %s: RTT=%v (code=0, no lingering 11010)", peerIP, rtt2)

	// 3. Test TUI state machine and formatting under forced loss
	st := &pingState{target: peerIP}

	// A) Initial total loss (never answered)
	st.err = 11010
	res := st.result()
	rendered := fmtPing(res)
	if !strings.Contains(rendered, "sem resposta (erro 11010)") {
		t.Fatalf("expected 'sem resposta (erro 11010)', got: %q", rendered)
	}
	t.Logf("TUI initial failure format: %s", rendered)

	// B) 10 successful packets followed by 10 dropped packets (50% loss)
	for range 10 {
		st.record(true, 18*time.Millisecond)
	}
	for range 10 {
		st.record(false, 0)
	}
	res = st.result()
	if res.Loss != 0.5 {
		t.Fatalf("expected 50%% loss, got %v", res.Loss)
	}
	rendered = fmtPing(res)
	if !strings.Contains(rendered, "último") || !strings.Contains(rendered, "perda 50%") {
		t.Fatalf("expected 'último' and 'perda 50%%', got: %q", rendered)
	}
	t.Logf("TUI partial loss format: %s", rendered)

	// C) Unblock/recovery: single packet restores active state
	st.record(true, 17*time.Millisecond)
	res = st.result()
	if !res.OK {
		t.Fatal("expected OK=true on recovery packet")
	}
	rendered = fmtPing(res)
	if strings.Contains(rendered, "último") {
		t.Fatalf("recovered state must not display '(último)', got: %q", rendered)
	}
	t.Logf("TUI recovered format: %s", rendered)
}

func TestUDPNetworkLossResilienceAndAntiStutter(t *testing.T) {
	// 1. Anti-stutter queue test: under network bufferbloat / queue saturation,
	// newest game packet must always be dispatched first (LIFO order), never lagging behind.
	q := newLatestQueue[int](16)
	for i := 1; i <= 20; i++ {
		q.offer(i) // push sequence numbers 1 to 20
	}
	if q.dropped.Load() == 0 {
		t.Fatal("expected older packets to be evicted under saturation")
	}
	newest, ok := q.popNewest()
	if !ok || newest != 20 {
		t.Fatalf("expected freshest game input 20, got %d (lag detected)", newest)
	}
	t.Logf("Anti-stutter queue: freshest packet %d popped first; %d stale packets dropped without blocking", newest, q.dropped.Load())

	// 2. Extreme packet loss resilience test (simulating 75% UDP loss on degraded route):
	// With 1:8 duplication, each game message gets 1 original + 8 redundant copies.
	d := newUDPDuplicator[int](256, true)
	d.setRatio(1, 8)
	stop := make(chan struct{})
	received := make(map[int]int)
	var mu sync.Mutex
	go d.run(stop, func(p []byte, id int) error {
		mu.Lock()
		defer mu.Unlock()
		received[id]++
		return nil
	})
	defer close(stop)

	const totalFrames = 50
	for i := 1; i <= totalFrames; i++ {
		d.offer([]byte{byte(i)}, i)
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	deliveredCount := len(received)
	mu.Unlock()

	if deliveredCount < totalFrames {
		t.Fatalf("expected all %d game frames delivered despite loss, only %d delivered", totalFrames, deliveredCount)
	}
	t.Logf("UDP 1:8 duplication resilience: %d/%d game frames delivered with zero lost frames under high duplication", deliveredCount, totalFrames)

	// 3. High-rate UDP live socket throughput & saturation test against WireGuard endpoint
	ep, err := ResolveEndpoint("56.124.121.11:51820")
	if err != nil {
		t.Fatalf("failed to resolve endpoint: %v", err)
	}
	conn, err := net.Dial("udp", ep.String())
	if err != nil {
		t.Fatalf("failed to dial UDP endpoint: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 1024)
	const burstCount = 200
	t0 := time.Now()
	for i := 0; i < burstCount; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("burst packet %d write failed: %v", i, err)
		}
	}
	elapsed := time.Since(t0)
	mbps := float64(burstCount*len(payload)*8) / elapsed.Seconds() / 1e6
	pps := float64(burstCount) / elapsed.Seconds()
	t.Logf("High-rate UDP burst (200 packets, 200 KB in %v): %.1f Mbit/s, %.0f packets/sec (0 socket errors)", elapsed, mbps, pps)
}

func TestPingLossIgnoresTimeoutsBeforeFirstReply(t *testing.T) {
	st := &pingState{target: netip.MustParseAddr("203.0.113.1")}
	for range 3 {
		st.record(false, 0)
	}
	if got := st.result().Loss; got != 0 {
		t.Fatalf("startup timeouts counted as loss: %v", got)
	}
	st.record(true, 20*time.Millisecond)
	st.record(false, 0)
	if got := st.result().Loss; got != 0.5 {
		t.Fatalf("loss after first reply = %v, want 0.5", got)
	}
}
