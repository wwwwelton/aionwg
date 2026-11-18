package app

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"
)

// Benchmarks for the portable pieces of the packet hot path. They cannot see
// WinDivert, Wintun or the network: they bound what the program itself adds
// per packet. Run: go test ./internal/app -run '^$' -bench PacketPath -benchmem

// benchJob mirrors outboundUDPJob (two slices and a path byte).
type benchJob struct {
	packet, copyUDP []byte
	path            uint8
}

var benchGamePacket = buildUDP4(netip.MustParseAddr("192.168.0.10"), netip.MustParseAddr("203.0.113.9"), 50000, 7777, make([]byte, 96))

func BenchmarkPacketPathParseAndChecksum(b *testing.B) {
	b.ReportAllocs()
	buf := make([]byte, len(benchGamePacket))
	src := netip.MustParseAddr("172.16.0.2")
	for b.Loop() {
		copy(buf, benchGamePacket)
		p, ok := parsePacket(buf)
		if !ok {
			b.Fatal("parse")
		}
		setSrc(buf, &p, src)
		fixChecksums(buf, &p)
	}
}

func BenchmarkPacketPathCloneRecycle(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		q := clonePktBuf(benchGamePacket)
		putPktBuf(q)
	}
}

// With the garbage collector running (the Go heap is never idle in the real
// program), pooled buffers are dropped and must be allocated again.
func BenchmarkPacketPathCloneRecycleUnderGC(b *testing.B) {
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		q := clonePktBuf(benchGamePacket)
		putPktBuf(q)
		if i++; i%2000 == 0 {
			runtime.GC()
		}
	}
}

// One producer saturating a bounded queue: every offer evicts the oldest item.
func BenchmarkPacketPathQueueSaturated(b *testing.B) {
	b.ReportAllocs()
	q := newLatestQueue[benchJob](128)
	job := benchJob{packet: benchGamePacket}
	for b.Loop() {
		q.offer(job)
	}
}

// Producer and consumer together, as in the engine.
func BenchmarkPacketPathQueueProducerConsumer(b *testing.B) {
	b.ReportAllocs()
	q := newLatestQueue[benchJob](128)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); q.run(stop, func(benchJob) {}) }()
	job := benchJob{packet: benchGamePacket}
	for b.Loop() {
		q.offer(job)
	}
	close(stop)
	wg.Wait()
}

func BenchmarkPacketPathSplitTunInjectRead(b *testing.B) {
	b.ReportAllocs()
	t := newSplitTun(1420)
	bufs := make([][]byte, t.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, len(bufs))
	for b.Loop() {
		t.inject(clonePktBuf(benchGamePacket))
		if n, err := t.Read(bufs, sizes, 16); err != nil || n != 1 {
			b.Fatal(n, err)
		}
	}
}

// gameServer(), Stats() and housekeeping scan the whole NAT table while holding
// the lock the capture path needs for every packet; this bounds one such stall.
func BenchmarkPacketPathNatScan2000(b *testing.B) {
	b.ReportAllocs()
	type entry struct {
		local, remote netip.Addr
		remotePort    uint16
		last          int64
		game          bool
	}
	var mu sync.Mutex
	m := make(map[[3]uint16]*entry, 2000)
	for i := 0; i < 2000; i++ {
		m[[3]uint16{6, uint16(i), 0}] = &entry{last: int64(i), game: i%7 == 0}
	}
	for b.Loop() {
		mu.Lock()
		var best int64
		for _, v := range m {
			if v.game && v.last > best {
				best = v.last
			}
		}
		mu.Unlock()
	}
}
