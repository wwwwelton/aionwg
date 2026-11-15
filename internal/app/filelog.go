package app

// File log for diagnosing drops. The TUI log lives only in memory, so a failure
// that ends the game session (or the program) leaves nothing to read. This keeps
// the same lines on disk without ever making a packet thread or the UI wait for
// the disk: writers hand lines to a bounded channel and one goroutine writes.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// fileLogMax bounds one file. The active file is renamed to ".1" when it
	// would pass this, replacing the previous ".1", so disk use stays under
	// about twice this value.
	fileLogMax = 2 << 20
	// fileLogQueue bounds lines waiting for the disk. Past it lines are counted
	// and dropped rather than blocking a caller.
	fileLogQueue = 1024
)

// fileLog appends timestamped lines to a size-bounded file.
type fileLog struct {
	path    string
	queue   chan string
	done    chan struct{}
	closed  sync.Once
	mu      sync.RWMutex
	stopped bool
	dropped atomic.Uint64
	now     func() time.Time // injectable for tests
}

// openFileLog starts the writer. A directory or file that cannot be opened is
// an error the caller may ignore: logging to disk is diagnostic only.
func openFileLog(path string) (*fileLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Prove the file is writable now, so the caller learns about it up front
	// rather than losing every line silently later.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	l := &fileLog{
		path:  path,
		queue: make(chan string, fileLogQueue),
		done:  make(chan struct{}),
		now:   time.Now,
	}
	go l.run()
	return l, nil
}

// Printf queues one line. It never blocks: if the writer cannot keep up the
// line is dropped and counted, and the count is written once the queue drains.
func (l *fileLog) Printf(format string, a ...any) {
	if l == nil {
		return
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.stopped {
		return
	}
	line := l.now().Format("2006-01-02 15:04:05.000 ") + fmt.Sprintf(format, a...)
	select {
	case l.queue <- line:
	default:
		l.dropped.Add(1)
	}
}

// Close flushes queued lines and stops the writer.
func (l *fileLog) Close() {
	if l == nil {
		return
	}
	l.closed.Do(func() {
		l.mu.Lock()
		l.stopped = true
		close(l.queue)
		l.mu.Unlock()
		<-l.done
	})
}

func (l *fileLog) run() {
	defer close(l.done)
	var f *os.File
	var size int64
	open := func() bool {
		var err error
		f, err = os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			f = nil
			return false
		}
		if st, err := f.Stat(); err == nil {
			size = st.Size()
		}
		return true
	}
	write := func(line string) {
		if len(line) >= fileLogMax {
			const suffix = " [truncado]"
			line = line[:fileLogMax-len(suffix)-1] + suffix
		}
		if f == nil && !open() {
			return // disk unavailable: drop, never block or crash
		}
		if size+int64(len(line))+1 > fileLogMax {
			f.Close()
			f = nil
			if err := os.Remove(l.path + ".1"); err != nil && !os.IsNotExist(err) {
				return
			}
			if err := os.Rename(l.path, l.path+".1"); err != nil {
				return
			}
			if !open() {
				return
			}
		}
		n, err := f.WriteString(line + "\n")
		size += int64(n)
		if err != nil {
			f.Close()
			f = nil
		}
	}
	for line := range l.queue {
		if d := l.dropped.Swap(0); d > 0 {
			write(fmt.Sprintf("%s [aviso] %d linha(s) de log descartada(s): fila cheia",
				l.now().Format("2006-01-02 15:04:05.000"), d))
		}
		write(line)
	}
	if f != nil {
		f.Close()
	}
}

// healthSample is what the periodic snapshot records. Plain numbers, so the
// formatting is portable and testable; the engine fills it from Stats.
type healthSample struct {
	HandshakeAgeSec  int64 // seconds since the last WireGuard handshake; -1 = never
	PingTunnelMs     int   // 0 = no reply
	PingLossPct      int
	PingGameMs       int    // through the tunnel to the game server; 0 = no reply
	PingGameDirectMs int    // straight to the game server, outside the tunnel; 0 = no reply
	CapturedPkts     uint64 // packets sent into the tunnel
	InjectedPkts     uint64 // packets returned to the apps
	InjectErr        uint64
	NoNAT            uint64 // answers with no matching flow
	QueueFull        uint64 // tunnel queue overflowed
	Flows            int
	MirrorOn         bool
	MirrorFlows      int    // established mirror connections
	MeterPackets     uint64 // packets copied into the AionWG-Meter adapter
	MeterRingFull    uint64 // copies dropped because the meter ring was full
}

// formatHealth renders cur as one line. Counters are shown with their change
// since prev ("+n"): what betrays a drop is a counter that stops rising or one
// that jumps, not its absolute value. It returns "" when nothing changed since
// prev, so a steady idle state does not fill the file.
func formatHealth(cur, prev healthSample) string {
	if cur == prev {
		return ""
	}
	d := func(a, b uint64) uint64 {
		if a < b {
			return a // counter reset (reconnect): show the new absolute value
		}
		return a - b
	}
	hs := "nunca"
	if cur.HandshakeAgeSec >= 0 {
		hs = fmt.Sprintf("%ds", cur.HandshakeAgeSec)
	}
	s := fmt.Sprintf("[saude] handshake=%s ping=%dms perda=%d%% fluxos=%d "+
		"entrou+%d voltou+%d erro_inj+%d sem_fluxo+%d fila_cheia+%d",
		hs, cur.PingTunnelMs, cur.PingLossPct, cur.Flows,
		d(cur.CapturedPkts, prev.CapturedPkts), d(cur.InjectedPkts, prev.InjectedPkts),
		d(cur.InjectErr, prev.InjectErr), d(cur.NoNAT, prev.NoNAT), d(cur.QueueFull, prev.QueueFull))
	if cur.PingGameMs > 0 || cur.PingGameDirectMs > 0 {
		s += fmt.Sprintf(" jogo=%dms direto=%dms", cur.PingGameMs, cur.PingGameDirectMs)
		if cur.PingGameMs > 0 && cur.PingGameDirectMs > 0 {
			s += fmt.Sprintf(" custo_tunel=%+dms", cur.PingGameMs-cur.PingGameDirectMs)
		}
	}
	if cur.MirrorOn {
		s += fmt.Sprintf(" espelho=%d_fluxos meter+%d meter_cheio+%d",
			cur.MirrorFlows, d(cur.MeterPackets, prev.MeterPackets), d(cur.MeterRingFull, prev.MeterRingFull))
	}
	return s
}
