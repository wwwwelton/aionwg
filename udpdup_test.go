package main

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestUDPDupOneCopyAndOriginalUnchanged(t *testing.T) {
	d := newUDPDuplicator[int](4, true)
	pkt := []byte{1, 2, 3, 4}
	d.offer(pkt, 7)
	pkt[0] = 99 // simulate WinDivert reusing the original buffer
	stop := make(chan struct{})
	got := make(chan []byte, 1)
	go d.run(stop, func(p []byte, a int) error {
		if a != 7 {
			t.Errorf("address = %d", a)
		}
		got <- p
		return nil
	})
	defer close(stop)
	select {
	case copy := <-got:
		if len(copy) != 4 || copy[0] != 1 {
			t.Fatalf("copy changed: %v", copy)
		}
		if pkt[0] != 99 {
			t.Fatal("original unexpectedly modified")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not dispatch one copy")
	}
}

func TestUDPDupNeverBlocksOnFullQueue(t *testing.T) {
	d := newUDPDuplicator[int](1, true)
	d.offer([]byte{1}, 1)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			d.offer([]byte{2}, 1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("packet capture blocked on duplicate queue")
	}
	if d.dropped.Load() == 0 {
		t.Fatal("expected best-effort drops")
	}
}

func TestUDPDupDisableDiscardsStaleQueuedPackets(t *testing.T) {
	d := newUDPDuplicator[int](2, true)
	d.offer([]byte{1}, 1)
	d.setEnabled(false)
	d.setEnabled(true)
	d.offer([]byte{2}, 2)
	stop := make(chan struct{})
	var mu sync.Mutex
	got := []int{}
	complete := make(chan struct{})
	go d.run(stop, func(_ []byte, a int) error {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		if a == 2 {
			close(complete)
		}
		return nil
	})
	defer close(stop)
	select {
	case <-complete:
	case <-time.After(time.Second):
		t.Fatal("worker stalled")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("unexpected sends: %v", got)
	}
	if d.dropped.Load() != 1 {
		t.Fatalf("expected stale packet dropped, got %d", d.dropped.Load())
	}
}

func TestUDPDupSendErrorCount(t *testing.T) {
	d := newUDPDuplicator[int](1, true)
	d.offer([]byte{1}, 0)
	stop := make(chan struct{})
	finished := make(chan struct{})
	go d.run(stop, func([]byte, int) error { close(finished); return errors.New("offline") })
	defer close(stop)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("worker stalled")
	}
	deadline := time.Now().Add(time.Second)
	for d.errors.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if d.errors.Load() != 1 {
		t.Fatalf("send errors = %d", d.errors.Load())
	}
}

func TestUDPOnlyGameSplitNonDNSIsDuplicated(t *testing.T) {
	cases := []struct {
		game, full bool
		proto      uint8
		port       uint16
		want       bool
	}{
		{true, false, protoUDP, 27015, true},
		{true, true, protoUDP, 27015, false},
		{false, false, protoUDP, 27015, false},
		{true, false, protoTCP, 27015, false},
		{true, false, protoUDP, 53, false},
		{true, false, protoUDP, 0, false},
	}
	for i, tc := range cases {
		if got := shouldDuplicateGameUDP(tc.game, tc.full, tc.proto, tc.port); got != tc.want {
			t.Errorf("case %d: got %v want %v", i, got, tc.want)
		}
	}
}

func TestUDPDupBatchReleasesGroupOnlyWhenFull(t *testing.T) {
	d := newUDPDuplicator[int](64, true)
	d.setRatio(3, true)
	d.offer([]byte("a"), 1)
	d.offer([]byte("b"), 1)
	if len(d.queue) != 0 {
		t.Fatalf("2 of 3 originals released %d copies early", len(d.queue))
	}
	d.offer([]byte("c"), 1)
	if len(d.queue) != 3 {
		t.Fatalf("3:3 group released %d copies, want 3", len(d.queue))
	}
	d.setRatio(2, false) // switching mode drops partial groups, 1:2 copies each original
	d.offer([]byte("d"), 1)
	if len(d.pending) != 0 || len(d.queue) != 5 {
		t.Fatalf("1:2 mode pending=%d queue=%d", len(d.pending), len(d.queue))
	}
}

func TestParseUDPRatio(t *testing.T) {
	for in, want := range map[string]struct {
		n     int
		batch bool
		ok    bool
	}{"3": {3, false, true}, "3:3": {3, true, true}, " 8 : 8 ": {8, true, true}, "2:3": {}, "0": {}, "9:9": {}, "x": {}} {
		n, b, ok := parseUDPRatio(in)
		if n != want.n || b != want.batch || ok != want.ok {
			t.Errorf("%q => %d,%v,%v want %+v", in, n, b, ok, want)
		}
	}
}
