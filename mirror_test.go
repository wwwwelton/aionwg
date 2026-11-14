package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestReasmOrder(t *testing.T) {
	var r reasm
	var got []byte
	emit := func(b []byte) { got = append(got, b...) }
	r.syn(0xFFFFFFF0) // wraps around 2^32
	base := uint32(0xFFFFFFF1)
	r.push(base+6, []byte("WORLD"), emit) // out of order
	r.push(base, []byte("HELLO "), emit)
	r.push(base, []byte("HELLO "), emit)   // retransmission
	r.push(base+3, []byte("LO WOR"), emit) // overlap
	r.push(base+11, []byte("!!"), emit)
	if string(got) != "HELLO WORLD!!" {
		t.Fatalf("got %q", got)
	}
}

func TestReasmReplacingPendingSegmentDoesNotInflateLimit(t *testing.T) {
	var r reasm
	r.syn(100)
	r.push(105, []byte("ab"), func([]byte) {})
	r.push(105, []byte("abcd"), func([]byte) {})
	if r.pendBytes != 4 {
		t.Fatalf("pending bytes = %d, want 4", r.pendBytes)
	}
	var got []byte
	r.push(101, []byte("1234"), func(b []byte) { got = append(got, b...) })
	if string(got) != "1234abcd" || r.pendBytes != 0 {
		t.Fatalf("stream=%q pending=%d", got, r.pendBytes)
	}
}

func TestMirrorSetupAfterCloseDoesNotOpenListener(t *testing.T) {
	m := newMirror(true, t.Logf)
	m.Close()
	f := &mirrorFlow{serverPort: 0, done: make(chan struct{})}
	m.setup(f)
	if len(m.listeners) != 0 {
		t.Fatal("setup recreated a listener after Close")
	}
}

// mkTCP builds an IPv4 TCP packet.
func mkTCP(src, dst string, sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, protoTCP
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint32(b[24:], seq)
	b[32] = 5 << 4
	b[33] = flags
	copy(b[40:], payload)
	return b
}

func TestMirrorLoopback(t *testing.T) {
	var mu sync.Mutex
	got := map[int]*bytes.Buffer{dirC2S: {}, dirS2C: {}}
	mirrorPeerRead = func(dir int, b []byte) {
		mu.Lock()
		got[dir].Write(b)
		mu.Unlock()
	}
	defer func() { mirrorPeerRead = nil }()

	m := newMirror(true, t.Logf)
	defer m.Close()
	feed := func(out bool, pkt []byte) {
		p, ok := parsePacket(pkt)
		if !ok {
			t.Fatal("parse")
		}
		m.packet(out, pkt, &p)
	}
	game, srv := "192.168.0.10", "203.0.113.5"
	feed(true, mkTCP(game, srv, 50555, 47123, 1000, 0x02, nil))  // SYN
	feed(false, mkTCP(srv, game, 47123, 50555, 9000, 0x12, nil)) // SYN-ACK
	feed(true, mkTCP(game, srv, 50555, 47123, 1001, 0x18, []byte("login")))
	feed(false, mkTCP(srv, game, 47123, 50555, 9006, 0x18, []byte("-damage:999"))) // out of order
	feed(false, mkTCP(srv, game, 47123, 50555, 9001, 0x18, []byte("hello")))
	feed(false, mkTCP(srv, game, 47123, 50555, 9001, 0x18, []byte("hello"))) // retransmit

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		a, b := got[dirC2S].String(), got[dirS2C].String()
		mu.Unlock()
		if a == "login" && b == "hello-damage:999" {
			fl := m.Flows()
			t.Logf("mirror flows: %v", fl)
			if len(fl) != 1 {
				t.Fatal("expected one flow")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("c2s=%q s2c=%q", got[dirC2S].String(), got[dirS2C].String())
}

func feedPkt(m *mirror, out bool, pkt []byte) {
	p, ok := parsePacket(pkt)
	if ok {
		m.packet(out, pkt, &p)
	}
}

func TestMirrorDisabledNeverCreatesFlowConcurrently(t *testing.T) {
	m := newMirror(true, t.Logf)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", uint16(40000+i), 443, 1, 0x02, nil))
			}
		}(i)
	}
	m.SetEnabled(false)
	wg.Wait()
	m.SetEnabled(false)
	m.mu.Lock()
	n := len(m.flows)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("flows after disable = %d", n)
	}
	m.Close()
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 41000, 443, 1, 0x02, nil))
	if len(m.flows) != 0 {
		t.Fatal("flow created after Close")
	}
}

func TestMirrorEndOfFlowStartsOneGoroutine(t *testing.T) {
	m := newMirror(true, t.Logf)
	defer m.Close()
	mirrorEndSpawns.Store(0)
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 42000, 443, 1, 0x02, nil))
	for i := 0; i < 20; i++ {
		feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 42000, 443, 2, 0x04, nil))
	}
	if n := mirrorEndSpawns.Load(); n != 1 {
		t.Fatalf("end goroutines = %d, want 1", n)
	}
}

func TestMirrorClosedFlowIsReplacedBySyn(t *testing.T) {
	m := newMirror(true, t.Logf)
	defer m.Close()
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 43000, 443, 1, 0x02, nil))
	m.mu.Lock()
	old := m.flows[43000]
	m.mu.Unlock()
	old.close()
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 43000, 443, 100, 0x02, nil))
	m.mu.Lock()
	cur := m.flows[43000]
	m.mu.Unlock()
	if cur == nil || cur == old {
		t.Fatal("closed flow was not replaced")
	}
}

func TestMirrorMeasuresAckAndReplyRTT(t *testing.T) {
	m := newMirror(true, t.Logf)
	defer m.Close()
	withAck := func(b []byte, ack uint32) []byte { binary.BigEndian.PutUint32(b[28:], ack); return b }
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 44000, 443, 100, 0x02, nil))
	feedPkt(m, true, mkTCP("10.0.0.2", "1.2.3.4", 44000, 443, 101, 0x18, []byte("hello")))
	time.Sleep(40 * time.Millisecond)
	feedPkt(m, false, withAck(mkTCP("1.2.3.4", "10.0.0.2", 443, 44000, 500, 0x10, nil), 105)) // does not cover seq 106: no sample
	feedPkt(m, false, withAck(mkTCP("1.2.3.4", "10.0.0.2", 443, 44000, 500, 0x10, nil), 106))
	time.Sleep(30 * time.Millisecond)
	feedPkt(m, false, withAck(mkTCP("1.2.3.4", "10.0.0.2", 443, 44000, 500, 0x18, []byte("reply")), 106))
	ack, resp := m.RTT()
	if ack.N != 1 || ack.Last < 40*time.Millisecond || ack.Last > 70*time.Millisecond {
		t.Fatalf("ack rtt = %+v", ack)
	}
	if resp.N != 1 || resp.Last < 70*time.Millisecond {
		t.Fatalf("reply rtt = %+v", resp)
	}
}
