package main

// "Modo espelho" for packet-based DPS meters (NotMeter, Shugo.gg, A2Tools…).
//
// With the tunnel on, the game's packets leave the PC encrypted, so Npcap on
// the network card only sees WireGuard. The mirror rebuilds each game TCP
// stream (both directions, in order, without retransmissions) and replays it
// over a REAL TCP connection on 127.0.0.1 — the same shape ExitLag/VPNs give
// the meters on the "Npcap Loopback Adapter":
//
//     client 127.0.0.1:<game local port>  ⇄  server 127.0.0.1:<game server port>
//
// Ports are copied from the real connection whenever they are free.

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	dirC2S = 0 // client → server (game → server)
	dirS2C = 1 // server → client
)

// mirrorPeerRead is a test hook: receives what arrives on the far side.
var mirrorPeerRead func(dir int, b []byte)

func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

// reasm puts one direction of a TCP stream back in order.
type reasm struct {
	init      bool
	next      uint32
	pending   map[uint32][]byte
	pendBytes int
}

const maxPending = 4 << 20

func (r *reasm) syn(seq uint32) {
	r.init, r.next = true, seq+1
	r.pending, r.pendBytes = nil, 0
}

func (r *reasm) push(seq uint32, data []byte, emit func([]byte)) {
	if len(data) == 0 {
		return
	}
	if !r.init {
		r.init, r.next = true, seq
	}
	end := seq + uint32(len(data))
	if !seqLess(r.next, end) { // entirely old (retransmission)
		return
	}
	if seqLess(seq, r.next) { // partial overlap: keep the new tail
		data = data[r.next-seq:]
		seq = r.next
	}
	if seq == r.next {
		emit(data)
		r.next = end
		r.drain(emit)
		return
	}
	// future segment: hold it until the gap is filled
	if r.pending == nil {
		r.pending = map[uint32][]byte{}
	}
	if old, ok := r.pending[seq]; ok && len(old) >= len(data) {
		return
	}
	r.pendBytes -= len(r.pending[seq])
	r.pending[seq] = append([]byte(nil), data...)
	r.pendBytes += len(data)
	if r.pendBytes > maxPending { // gap never filled: skip over it
		first := true
		var min uint32
		for s := range r.pending {
			if first || seqLess(s, min) {
				min, first = s, false
			}
		}
		r.next = min
		r.drain(emit)
	}
}

func (r *reasm) drain(emit func([]byte)) {
	for progress := true; progress && len(r.pending) > 0; {
		progress = false
		for s, d := range r.pending {
			e := s + uint32(len(d))
			if !seqLess(r.next, e) { // already covered
				delete(r.pending, s)
				r.pendBytes -= len(d)
				continue
			}
			if !seqLess(r.next, s) { // s <= next < e
				emit(d[r.next-s:])
				r.next = e
				delete(r.pending, s)
				r.pendBytes -= len(d)
				progress = true
			}
		}
	}
}

type mirrorFlow struct {
	localPort, serverPort uint16
	mu                    sync.Mutex
	dir                   [2]reasm
	out                   [2]chan []byte
	done                  chan struct{}
	once                  sync.Once
	fin                   [2]bool
	ackWait, respWait     bool // an outbound payload awaits its ACK / first reply payload (under mu)
	outEnd                uint32
	outAt, respAt         time.Time
	ending                bool // end-of-flow goroutine already started (under mu)
	last                  time.Time
	addr                  string // "127.0.0.1:x ⇄ 127.0.0.1:y" once connected
	ready                 atomic.Bool
}

func (f *mirrorFlow) close() { f.once.Do(func() { close(f.done) }) }

func (f *mirrorFlow) send(dir int, b []byte) {
	select {
	case f.out[dir] <- append([]byte(nil), b...):
	default: // writer stalled; dropping is better than blocking the game
	}
}

type mirror struct {
	enabled   atomic.Bool
	noLoopback atomic.Bool // true: no TCP replay on 127.0.0.1; meter feed is written separately
	rttAck    rttStat // outbound payload -> ACK that covers it, as seen by the mirror
	rttResp   rttStat // outbound payload -> first payload back (application-level)
	logf      func(string, ...any)
	trace     func(string, ...any) // disk-only diagnostics; too chatty for the screen
	mu        sync.Mutex
	flows     map[uint16]*mirrorFlow // by game local port
	setupMu   sync.Mutex
	listeners map[uint16]net.Listener // by server port
	stop      chan struct{}
	stopOnce  sync.Once
}

// rttStat keeps the last and a smoothed (1/8) round-trip sample; lock-free,
// a lost update only skips one sample.
type rttStat struct {
	last, avg atomic.Int64
	n         atomic.Uint64
}

func (r *rttStat) add(d time.Duration) {
	if d <= 0 {
		return
	}
	r.last.Store(int64(d))
	r.n.Add(1)
	if old := r.avg.Load(); old == 0 {
		r.avg.Store(int64(d))
	} else {
		r.avg.Store(old + (int64(d)-old)/8)
	}
}

// MirrorRTT is a snapshot of rttStat.
type MirrorRTT struct {
	Last, Avg time.Duration
	N         uint64
}

func (r *rttStat) snapshot() MirrorRTT {
	return MirrorRTT{time.Duration(r.last.Load()), time.Duration(r.avg.Load()), r.n.Load()}
}

// RTT returns the ACK round trip and the request->reply time seen by the mirror.
func (m *mirror) RTT() (ack, resp MirrorRTT) { return m.rttAck.snapshot(), m.rttResp.snapshot() }

func newMirror(on bool, logf func(string, ...any)) *mirror {
	m := &mirror{
		logf:      logf,
		trace:     func(string, ...any) {},
		flows:     map[uint16]*mirrorFlow{},
		listeners: map[uint16]net.Listener{},
		stop:      make(chan struct{}),
	}
	m.enabled.Store(on)
	go m.janitor()
	return m
}

func (m *mirror) SetEnabled(on bool) {
	m.enabled.Store(on)
	if !on {
		m.mu.Lock()
		for k, f := range m.flows {
			f.close()
			delete(m.flows, k)
		}
		m.mu.Unlock()
	}
}

// Flows returns the active mirrored connections.
func (m *mirror) Flows() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, f := range m.flows {
		if f.ready.Load() {
			out = append(out, f.addr)
		}
	}
	return out
}

// packet feeds one game TCP packet (either direction, plaintext).
func (m *mirror) packet(outbound bool, pkt []byte, p *pktInfo) {
	if !m.enabled.Load() || m.noLoopback.Load() || p.proto != protoTCP {
		return
	}
	t := pkt[p.l4:pktLen(pkt, p)]
	if len(t) < 20 {
		return
	}
	doff := int(t[12]>>4) * 4
	if doff < 20 || doff > len(t) {
		return
	}
	seq := binary.BigEndian.Uint32(t[4:])
	flags := t[13]
	syn, ack, fin, rst := flags&0x02 != 0, flags&0x10 != 0, flags&0x01 != 0, flags&0x04 != 0
	payload := t[doff:]

	local, server, dir := p.srcPort, p.dstPort, dirC2S
	if !outbound {
		local, server, dir = p.dstPort, p.srcPort, dirS2C
	}

	m.mu.Lock()
	select {
	case <-m.stop:
		m.mu.Unlock()
		return
	default:
	}
	if !m.enabled.Load() { // re-check under mu: SetEnabled(false) clears flows under it
		m.mu.Unlock()
		return
	}
	f := m.flows[local]
	if f != nil {
		select {
		case <-f.done: // closed (failed setup / ended): a new flow may replace it
			f = nil
		default:
		}
	}
	if outbound && syn && !ack { // new connection from the game
		if f != nil {
			f.close()
		}
		f = nil
	}
	if f == nil {
		if !(syn || len(payload) > 0) {
			m.mu.Unlock()
			return
		}
		f = &mirrorFlow{
			localPort: local, serverPort: server,
			out:  [2]chan []byte{make(chan []byte, 8192), make(chan []byte, 8192)},
			done: make(chan struct{}),
		}
		m.flows[local] = f
		go m.setup(f)
	}
	m.mu.Unlock()

	f.mu.Lock()
	f.last = time.Now()
	if syn && !f.dir[dir].init {
		f.dir[dir].syn(seq)
	}
	if syn {
		seq++
	}
	f.dir[dir].push(seq, payload, func(b []byte) { f.send(dir, b) })
	if outbound {
		if len(payload) > 0 {
			if !f.ackWait {
				f.ackWait, f.outEnd, f.outAt = true, seq+uint32(len(payload)), f.last
			}
			if !f.respWait {
				f.respWait, f.respAt = true, f.last
			}
		}
	} else {
		if f.ackWait && ack && int32(binary.BigEndian.Uint32(t[8:])-f.outEnd) >= 0 {
			f.ackWait = false
			m.rttAck.add(f.last.Sub(f.outAt))
		}
		if f.respWait && len(payload) > 0 {
			f.respWait = false
			m.rttResp.add(f.last.Sub(f.respAt))
		}
	}
	if fin {
		f.fin[dir] = true
	}
	end := (rst || (f.fin[0] && f.fin[1])) && !f.ending
	if end {
		f.ending = true
	}
	f.mu.Unlock()
	if end {
		mirrorEndSpawns.Add(1)
		go func() {
			time.Sleep(time.Second) // let the writers flush
			f.close()
			m.mu.Lock()
			if m.flows[local] == f {
				delete(m.flows, local)
			}
			m.mu.Unlock()
		}()
	}
}

// mirrorEndSpawns counts end-of-flow goroutines (tests assert one per flow).
var mirrorEndSpawns atomic.Int32

func (m *mirror) listener(port uint16) (net.Listener, error) {
	if ln := m.listeners[port]; ln != nil {
		return ln, nil
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln, err = net.Listen("tcp4", "127.0.0.1:0") // server port busy: any port
		if err != nil {
			return nil, err
		}
	}
	m.listeners[port] = ln
	return ln, nil
}

func (m *mirror) setup(f *mirrorFlow) {
	queued := time.Now()
	m.setupMu.Lock()
	select {
	case <-m.stop:
		m.setupMu.Unlock()
		return
	case <-f.done:
		m.setupMu.Unlock()
		return
	default:
	}
	waited := time.Since(queued) // time spent behind other flows' setup
	t0 := time.Now()
	ln, err := m.listener(f.serverPort)
	var cli, srv net.Conn
	if err == nil {
		cli, err = dialMirror(f.localPort, ln.Addr().String())
	}
	if err == nil {
		srv, err = acceptPeer(ln, cli.LocalAddr().String())
	}
	m.setupMu.Unlock()
	took := time.Since(t0)
	if err != nil {
		if cli != nil {
			cli.Close()
		}
		m.logf("espelho: falhou (%v)", err)
		m.trace("espelho: fluxo %d->%d FALHOU apos %s (esperou %s na fila): %v",
			f.localPort, f.serverPort, took.Round(time.Millisecond), waited.Round(time.Millisecond), err)
		f.close()
		m.mu.Lock()
		if m.flows[f.localPort] == f {
			delete(m.flows, f.localPort)
		}
		m.mu.Unlock()
		return
	}
	f.addr = fmt.Sprintf("%s ⇄ %s", cli.LocalAddr(), srv.LocalAddr())
	f.ready.Store(true)
	m.trace("espelho: fluxo %d->%d pronto em %s (esperou %s na fila)",
		f.localPort, f.serverPort, took.Round(time.Millisecond), waited.Round(time.Millisecond))
	go discard(cli, dirS2C)
	go discard(srv, dirC2S)
	go writer(cli, f.out[dirC2S], f.done)
	go writer(srv, f.out[dirS2C], f.done)
}

func acceptPeer(ln net.Listener, want string) (net.Conn, error) {
	tl, _ := ln.(*net.TCPListener)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if tl != nil {
			tl.SetDeadline(deadline)
		}
		c, err := ln.Accept()
		if err != nil {
			return nil, err
		}
		if c.RemoteAddr().String() == want {
			return c, nil
		}
		c.Close() // someone else connected to our port
	}
}

func discard(c net.Conn, dir int) {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 && mirrorPeerRead != nil {
			mirrorPeerRead(dir, append([]byte(nil), buf[:n]...))
		}
		if err != nil {
			return
		}
	}
}

func writer(c net.Conn, ch chan []byte, done chan struct{}) {
	defer c.Close()
	for {
		select {
		case b := <-ch:
			if _, err := c.Write(b); err != nil {
				return
			}
		case <-done:
			for {
				select {
				case b := <-ch:
					c.Write(b)
				default:
					if tc, ok := c.(*net.TCPConn); ok {
						tc.CloseWrite()
						time.Sleep(200 * time.Millisecond)
					}
					return
				}
			}
		}
	}
}

func (m *mirror) janitor() {
	tk := time.NewTicker(15 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-tk.C:
		}
		m.mu.Lock()
		for k, f := range m.flows {
			f.mu.Lock()
			idle := time.Since(f.last) > 3*time.Minute
			f.mu.Unlock()
			if idle {
				f.close()
				delete(m.flows, k)
			}
		}
		m.mu.Unlock()
	}
}

func (m *mirror) Close() {
	m.stopOnce.Do(func() {
		close(m.stop)
		m.mu.Lock()
		for k, f := range m.flows {
			f.close()
			delete(m.flows, k)
		}
		m.mu.Unlock()
		m.setupMu.Lock()
		for k, ln := range m.listeners {
			ln.Close()
			delete(m.listeners, k)
		}
		m.setupMu.Unlock()
	})
}

// dialMirror connects from 127.0.0.1:<game local port> when possible.
func dialMirror(localPort uint16, raddr string) (net.Conn, error) {
	if localPort != 0 {
		d := net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(localPort)},
			Control:   reuseAddrControl,
			Timeout:   time.Second,
		}
		if c, err := d.Dial("tcp4", raddr); err == nil {
			return c, nil
		}
	}
	d := net.Dialer{Timeout: time.Second}
	return d.Dial("tcp4", raddr)
}
