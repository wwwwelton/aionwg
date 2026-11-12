package main

// Secondary UDP copies are best-effort. The WireGuard primary path is not
// delayed by this queue. Each original datagram schedules copies (1:1, 2:1,
// etc), with the most RECENT datagram always first among pending copies.
// Copies use the direct Windows route and can be rejected as duplicates by the
// game server. Never claim this lowers ping.

import (
	"sync"
	"sync/atomic"
)

const (
	udpDupQueueSize = 256
	udpCopiesMax    = 8
)

// No TCP conversion: ForceUDP extends SECONDARY UDP copying to additional
// game endpoints; it cannot convert TCP sessions to UDP. DNS/LAN/endpoint
// traffic and full-tunnel mode remain excluded.
func shouldDuplicateGameUDP(isGame, fullTunnel bool, proto uint8, dstPort uint16) bool {
	return isGame && !fullTunnel && proto == protoUDP && dstPort != 53 && dstPort != 0
}

type udpDuplicateItem[A any] struct {
	packet     []byte
	address    A
	generation uint64
}

type udpDuplicator[A any] struct {
	enabled    atomic.Bool
	copies     atomic.Int32
	generation atomic.Uint64
	mu         sync.Mutex
	queue      []udpDuplicateItem[A]
	capacity   int
	notify     chan struct{}
	accepted   atomic.Uint64
	sent       atomic.Uint64
	dropped    atomic.Uint64
	errors     atomic.Uint64
}

func normalizeUDPCopies(n int) int {
	if n < 1 {
		return 1
	}
	if n > udpCopiesMax {
		return udpCopiesMax
	}
	return n
}

func newUDPDuplicator[A any](capacity int, enabled bool) *udpDuplicator[A] {
	if capacity < 1 {
		capacity = 1
	}
	d := &udpDuplicator[A]{capacity: capacity, notify: make(chan struct{}, 1)}
	d.enabled.Store(enabled)
	d.copies.Store(1)
	return d
}

func (d *udpDuplicator[A]) setEnabled(enabled bool) {
	// Stale queued jobs are invalidated on any transition.
	d.generation.Add(1)
	d.enabled.Store(enabled)
}

func (d *udpDuplicator[A]) setCopies(n int) {
	d.generation.Add(1)
	d.copies.Store(int32(normalizeUDPCopies(n)))
}

func (d *udpDuplicator[A]) offer(original []byte, address A) {
	if !d.enabled.Load() || len(original) == 0 {
		return
	}
	g := d.generation.Load()
	n := int(d.copies.Load())
	if !d.enabled.Load() || g != d.generation.Load() || n < 1 {
		return
	}
	// Capture buffers are reused: copy once and share immutable copy between jobs.
	pkt := append([]byte(nil), original...)
	d.mu.Lock()
	for i := 0; i < n; i++ {
		if len(d.queue) == d.capacity {
			var zero udpDuplicateItem[A]
			d.queue[0] = zero
			copy(d.queue, d.queue[1:])
			d.queue = d.queue[:len(d.queue)-1]
			d.dropped.Add(1)
		}
		d.queue = append(d.queue, udpDuplicateItem[A]{packet: pkt, address: address, generation: g})
		d.accepted.Add(1)
	}
	d.mu.Unlock()
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

func (d *udpDuplicator[A]) popNewest() (udpDuplicateItem[A], bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var zero udpDuplicateItem[A]
	n := len(d.queue)
	if n == 0 {
		return zero, false
	}
	item := d.queue[n-1]
	d.queue[n-1] = zero
	d.queue = d.queue[:n-1]
	return item, true
}

func (d *udpDuplicator[A]) run(stop <-chan struct{}, send func([]byte, A) error) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		job, ok := d.popNewest()
		if !ok {
			select {
			case <-stop:
				return
			case <-d.notify:
			}
			continue
		}
		if !d.enabled.Load() || job.generation != d.generation.Load() {
			d.dropped.Add(1)
			continue
		}
		if err := send(job.packet, job.address); err != nil {
			d.errors.Add(1)
		} else {
			d.sent.Add(1)
		}
	}
}
