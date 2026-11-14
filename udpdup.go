package main

// Secondary UDP copies are best-effort. The WireGuard primary path is not
// delayed by this queue. Each original datagram schedules copies (1:1, 2:1,
// etc), with the most RECENT datagram always first among pending copies.
// Copies go through the tunnel and can be rejected as duplicates by the
// game server. Never claim this lowers ping.

import (
	"fmt"
	"strconv"
	"strings"
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
	originals  atomic.Int32 // A: originals per group
	copies     atomic.Int32 // B: copies released per group
	generation atomic.Uint64
	mu         sync.Mutex
	queue      []udpDuplicateItem[A]
	pending    []udpDuplicateItem[A] // originals waiting for their group to fill
	capacity   int
	notify     chan struct{}
	accepted   atomic.Uint64
	sent       atomic.Uint64
	dropped    atomic.Uint64
	errors     atomic.Uint64
}

// udpRatioLabel renders the ratio as originals:copies.
func udpRatioLabel(originals, copies int) string {
	return fmt.Sprintf("%d:%d", normalizeUDPCopies(originals), normalizeUDPCopies(copies))
}

// parseUDPRatio accepts "B" (1:B) or "A:B": every A originals release B copies.
func parseUDPRatio(v string) (originals, copies int, ok bool) {
	a, b, hasColon := strings.Cut(strings.TrimSpace(v), ":")
	if !hasColon {
		b, a = a, "1"
	}
	originals, err1 := strconv.Atoi(strings.TrimSpace(a))
	copies, err2 := strconv.Atoi(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || originals < 1 || originals > udpCopiesMax || copies < 1 || copies > udpCopiesMax {
		return 0, 0, false
	}
	return originals, copies, true
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
	d.originals.Store(1)
	d.copies.Store(1)
	return d
}

func (d *udpDuplicator[A]) setEnabled(enabled bool) {
	// Stale queued jobs are invalidated on any transition.
	d.generation.Add(1)
	d.enabled.Store(enabled)
}

// setRatio sets A:B: once A originals arrived, B copies are queued, newest
// original first (1:B copies each original; A:A copies each original once).
func (d *udpDuplicator[A]) setRatio(originals, copies int) {
	// Store first, bump generation last: offer() rechecks the generation after
	// reading both values, so a torn A/B read is always discarded.
	d.originals.Store(int32(normalizeUDPCopies(originals)))
	d.copies.Store(int32(normalizeUDPCopies(copies)))
	d.generation.Add(1)
	d.mu.Lock()
	d.pending = nil
	d.mu.Unlock()
}

func (d *udpDuplicator[A]) offer(original []byte, address A) {
	if !d.enabled.Load() || len(original) == 0 {
		return
	}
	g := d.generation.Load()
	a, b := int(d.originals.Load()), int(d.copies.Load())
	if !d.enabled.Load() || g != d.generation.Load() || a < 1 || b < 1 {
		return
	}
	// Capture buffers are reused: copy once and share immutable copy between jobs.
	pkt := append([]byte(nil), original...)
	item := udpDuplicateItem[A]{packet: pkt, address: address, generation: g}
	d.mu.Lock()
	d.pending = append(d.pending, item)
	if len(d.pending) >= a {
		for k := 0; k < b; k++ {
			d.push(d.pending[len(d.pending)-1-k%len(d.pending)])
		}
		d.pending = d.pending[:0]
	}
	d.mu.Unlock()
	select {
	case d.notify <- struct{}{}:
	default:
	}
}

// push appends under d.mu, evicting the oldest entry when full.
func (d *udpDuplicator[A]) push(it udpDuplicateItem[A]) {
	if len(d.queue) == d.capacity {
		var zero udpDuplicateItem[A]
		d.queue[0] = zero
		copy(d.queue, d.queue[1:])
		d.queue = d.queue[:len(d.queue)-1]
		d.dropped.Add(1)
	}
	d.queue = append(d.queue, it)
	d.accepted.Add(1)
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
