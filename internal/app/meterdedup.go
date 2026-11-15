package app

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// meterDupWindow: replies to duplicated game UDP copies arrive within a few RTTs
// of each other; an identical reply inside this window is the same answer again.
const meterDupWindow = 100 * time.Millisecond

const meterDupSlots = 256

// meterDedup keeps the Npcap meter feed to one copy of each inbound reply. It
// filters only what is written to the meter; the game still receives every reply.
type meterDedup struct {
	mu      sync.Mutex
	ring    [meterDupSlots]meterDupEntry
	next    int
	dropped atomic.Uint64
}

type meterDupEntry struct {
	key uint64
	at  time.Time
}

// seen reports whether the same UDP ports and payload were already recorded within
// meterDupWindow, and records this packet. Empty payloads are never treated as dups.
func (d *meterDedup) seen(pkt []byte, p *pktInfo, now time.Time) bool {
	start, end := p.l4+8, pktLen(pkt, p)
	if start >= end {
		return false
	}
	h := fnv.New64a()
	h.Write([]byte{byte(p.srcPort >> 8), byte(p.srcPort), byte(p.dstPort >> 8), byte(p.dstPort)})
	h.Write(pkt[start:end])
	key := h.Sum64()

	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.ring {
		if e.key == key && now.Sub(e.at) < meterDupWindow && !e.at.IsZero() {
			d.dropped.Add(1)
			return true
		}
	}
	d.ring[d.next] = meterDupEntry{key: key, at: now}
	d.next = (d.next + 1) % meterDupSlots
	return false
}

// droppedCount is how many inbound replies were kept off the meter as duplicates.
func (d *meterDedup) droppedCount() uint64 { return d.dropped.Load() }
