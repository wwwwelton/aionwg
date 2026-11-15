package app

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
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func (t *splitTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n == 0 {
		select {
		case p := <-t.in:
			n += t.take(bufs[n], sizes[n:], offset, p)
		case <-t.closed:
			return 0, os.ErrClosed
		}
	}
	for n < len(bufs) {
		select {
		case p := <-t.in:
			n += t.take(bufs[n], sizes[n:], offset, p)
		default:
			return n, nil
		}
	}
	return n, nil
}

// take copies p into buf; a packet that does not fit (LSO/USO giants) is
// dropped, never truncated into a valid-looking shorter packet.
func (t *splitTun) take(buf []byte, sizes []int, offset int, p []byte) int {
	defer putPktBuf(p)
	if len(p) > len(buf)-offset {
		t.drops.Add(1)
		return 0
	}
	sizes[0] = copy(buf[offset:], p)
	return 1
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
		putPktBuf(p)
	}
}
