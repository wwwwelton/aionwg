//go:build windows

package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func gatedMonitor(calls *atomic.Int32, gate chan struct{}) *wfpMonitor {
	return &wfpMonitor{table: newTestTable(), dump: func(map[uint32]uint8) map[portKey]uint8 {
		calls.Add(1)
		<-gate
		return map[portKey]uint8{{protoUDP, 7000}: classGame}
	}}
}

func TestWFPInvalidateDoesNotBlockBehindDump(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	m := gatedMonitor(&calls, gate)
	go m.systemClass(protoUDP, 7000)
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	done := make(chan struct{})
	go func() { m.invalidateFallback(); close(done) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("invalidateFallback blocked behind the dump")
	}
	close(gate)
	// the dump began before the invalidation: nothing stale may be cached
	time.Sleep(20 * time.Millisecond)
	if _, ok := m.fallbackCache(); ok {
		t.Fatal("stale dump published after invalidation")
	}
}

func TestWFPConcurrentLookupsShareOneDump(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	m := gatedMonitor(&calls, gate)
	var wg sync.WaitGroup
	got := make([]uint8, 8)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i] = m.systemClass(protoUDP, 7000) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("dumps=%d, want 1", calls.Load())
	}
	for _, c := range got {
		if c != classGame {
			t.Fatalf("class=%d", c)
		}
	}
}
