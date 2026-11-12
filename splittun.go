package main

import (
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// ---------------------------------------------------------------- tun device

type splitTun struct {
	in        chan []byte
	events    chan tun.Event
	closed    chan struct{}
	once      sync.Once
	mtu       int
	onInbound func([]byte)
	drops     atomic.Uint64
}

func newSplitTun(mtu int) *splitTun {
	t := &splitTun{
		in:     make(chan []byte, 2048),
		events: make(chan tun.Event, 4),
		closed: make(chan struct{}),
		mtu:    mtu,
	}
	t.events <- tun.EventUp
	return t
}

func (t *splitTun) File() *os.File           { return nil }
func (t *splitTun) MTU() (int, error)        { return t.mtu, nil }
func (t *splitTun) Name() (string, error)    { return "aionwg", nil }
func (t *splitTun) Events() <-chan tun.Event { return t.events }
func (t *splitTun) BatchSize() int           { return 32 }

func (t *splitTun) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

func (t *splitTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var p []byte
	select {
	case p = <-t.in:
	case <-t.closed:
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], p)
	n := 1
	for n < len(bufs) {
		select {
		case p = <-t.in:
			sizes[n] = copy(bufs[n][offset:], p)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (t *splitTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if t.onInbound != nil {
			t.onInbound(b[offset:])
		}
	}
	return len(bufs), nil
}

// inject pushes a locally generated packet (e.g. ping) into the tunnel.
func (t *splitTun) inject(p []byte) {
	select {
	case t.in <- p:
	default:
		t.drops.Add(1)
	}
}
