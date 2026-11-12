package main

// latestQueue is a bounded non-blocking LIFO dispatch queue. When full, the
// oldest waiting item is evicted in favour of the newest. No network operation
// happens while its mutex is held. Reordering UDP application datagrams can
// affect game semantics: never enable this for TCP/DNS/ICMP.

import (
	"sync"
	"sync/atomic"
)

type latestQueue[T any] struct {
	mu      sync.Mutex
	items   []T
	cap     int
	notify  chan struct{}
	onDrop  func(T)
	dropped atomic.Uint64
	sent    atomic.Uint64
}

func newLatestQueue[T any](capacity int) *latestQueue[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &latestQueue[T]{cap: capacity, notify: make(chan struct{}, 1)}
}

// offer never waits for the consumer. A saturated queue discards the oldest waiting packet.
func (q *latestQueue[T]) offer(value T) {
	q.mu.Lock()
	if len(q.items) == q.cap {
		var zero T
		if q.onDrop != nil {
			q.onDrop(q.items[0])
		}
		q.items[0] = zero // release memory kept alive by the stale oldest item
		copy(q.items, q.items[1:])
		q.items = q.items[:len(q.items)-1]
		q.dropped.Add(1)
	}
	q.items = append(q.items, value)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *latestQueue[T]) popNewest() (T, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var zero T
	n := len(q.items)
	if n == 0 {
		return zero, false
	}
	item := q.items[n-1]
	q.items[n-1] = zero
	q.items = q.items[:n-1]
	return item, true
}

func (q *latestQueue[T]) run(stop <-chan struct{}, send func(T)) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if job, ok := q.popNewest(); ok {
			send(job)
			q.sent.Add(1)
			continue
		}
		select {
		case <-stop:
			return
		case <-q.notify:
		}
	}
}
