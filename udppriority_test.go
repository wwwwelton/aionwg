package main

import (
	"sync"
	"testing"
	"time"
)

func TestLatestQueueNewestFirstAndEvictsOldest(t *testing.T) {
	q := newLatestQueue[int](3)
	for _, n := range []int{1, 2, 3, 4} {
		q.offer(n)
	}
	if got := q.dropped.Load(); got != 1 {
		t.Fatalf("dropped %d", got)
	}
	for _, want := range []int{4, 3, 2} {
		got, ok := q.popNewest()
		if !ok || got != want {
			t.Fatalf("got %d, %v; want %d", got, ok, want)
		}
	}
	if _, ok := q.popNewest(); ok {
		t.Fatal("queue should be empty")
	}
}

func TestUDPDuplicatorRatioAndNewestFirst(t *testing.T) {
	d := newUDPDuplicator[int](16, true)
	d.setCopies(2)
	d.offer([]byte{1}, 1)
	d.offer([]byte{2}, 2)
	stop := make(chan struct{})
	got := make(chan int, 4)
	go d.run(stop, func(p []byte, a int) error {
		if len(p) != 1 || int(p[0]) != a {
			t.Errorf("wrong packet: %v (%d)", p, a)
		}
		got <- a
		return nil
	})
	defer close(stop)
	for i, want := range []int{2, 2, 1, 1} {
		select {
		case n := <-got:
			if n != want {
				t.Fatalf("packet %d: got %d want %d", i, n, want)
			}
		case <-time.After(time.Second):
			t.Fatal("worker timeout")
		}
	}
}

func TestUDPDuplicatorFreshnessBoundedConcurrency(t *testing.T) {
	d := newUDPDuplicator[int](8, true)
	d.setCopies(4)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				d.offer([]byte{byte(idx), byte(j)}, idx)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("capture blocked")
	}
	if got := d.dropped.Load(); got == 0 {
		t.Fatal("expected bounded queue to evict stale packets")
	}
	if got := d.accepted.Load(); got != 6*500*4 {
		t.Fatalf("accepted %d", got)
	}
}

func TestUDPDuplicateClampsRatio(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{-2, 1}, {0, 1}, {1, 1}, {2, 2}, {8, 8}, {99, 8}} {
		if got := normalizeUDPCopies(tc.in); got != tc.want {
			t.Errorf("%d => %d want %d", tc.in, got, tc.want)
		}
	}
}

func TestLatestQueueConcurrentProducerNeverBlocks(t *testing.T) {
	q := newLatestQueue[int](16)
	stop := make(chan struct{})
	var consumed sync.WaitGroup
	consumed.Add(1)
	go func() { defer consumed.Done(); q.run(stop, func(_ int) {}) }()
	var prod sync.WaitGroup
	for i := 0; i < 8; i++ {
		prod.Add(1)
		go func(id int) {
			defer prod.Done()
			for j := 0; j < 2000; j++ {
				q.offer(id*2000 + j)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { prod.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("latest queue blocked capture")
	}
	close(stop)
	consumed.Wait()
}
