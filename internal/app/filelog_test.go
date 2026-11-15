package app

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestLog(t *testing.T) (*fileLog, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "aionwg.log") // sub/ must be created
	l, err := openFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC) }
	return l, path
}

func TestFileLogWritesTimestampedLinesInOrder(t *testing.T) {
	l, path := newTestLog(t)
	for i := range 5 {
		l.Printf("linha %d", i)
	}
	l.Close() // flushes
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("got %d lines: %q", len(lines), lines)
	}
	for i, ln := range lines {
		want := "2026-01-02 03:04:05.006 linha " + string(rune('0'+i))
		if ln != want {
			t.Errorf("line %d = %q, want %q", i, ln, want)
		}
	}
}

// The user must be able to read the lines from just before a failure, and the
// log must never grow without bound.
func TestFileLogRotatesAndStaysBounded(t *testing.T) {
	l, path := newTestLog(t)
	chunk := strings.Repeat("x", 1000)
	total := fileLogMax/len(chunk)*3 + 7 // several times the limit
	for range total {
		l.Printf("%s", chunk)
		// keep the producer below the queue size so nothing is dropped here
		for len(l.queue) > fileLogQueue/2 {
			time.Sleep(time.Millisecond)
		}
	}
	l.Close()

	for _, p := range []string{path, path + ".1"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if st.Size() > fileLogMax {
			t.Errorf("%s is %d bytes, over the %d limit", p, st.Size(), fileLogMax)
		}
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("only one rotated file may be kept")
	}
	// the newest line must be in the active file: rotation keeps recent history
	b, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(b), chunk+"\n") {
		t.Error("the last line written is missing from the active file")
	}
}

// A drop must be visible: a silent gap in a diagnostic log looks like "nothing
// happened", which is the opposite of the truth.
func TestFileLogReportsDroppedLines(t *testing.T) {
	l, path := newTestLog(t)
	l.dropped.Store(3) // as if three lines were refused while the queue was full
	l.Printf("depois")
	l.Close()
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, "3 linha(s) de log descartada(s)") {
		t.Fatalf("drop count not reported:\n%s", s)
	}
	if !strings.Contains(s, "depois") {
		t.Fatalf("the line itself was lost:\n%s", s)
	}
}

// Printf is called from packet threads and the UI: it must never block, even
// when the writer is stalled.
func TestFileLogPrintfNeverBlocks(t *testing.T) {
	l := &fileLog{queue: make(chan string, 1), now: time.Now} // no writer goroutine: queue stays full
	done := make(chan struct{})
	go func() {
		for range 100 {
			l.Printf("x")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Printf blocked on a full queue")
	}
	if l.dropped.Load() != 99 {
		t.Fatalf("dropped = %d, want 99", l.dropped.Load())
	}
}

// Logging is diagnostic: a nil log (file could not be opened) must be harmless.
func TestFileLogNilIsSafe(t *testing.T) {
	var l *fileLog
	l.Printf("nada")
	l.Close()
}

func TestOpenFileLogFailsCleanlyWhenPathIsUnusable(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a file where a directory is needed
	if l, err := openFileLog(filepath.Join(blocker, "aionwg.log")); err == nil {
		l.Close()
		t.Fatal("expected an error when the parent is a file")
	}
}

func TestFileLogCloseWhileLogging(t *testing.T) {
	l, path := newTestLog(t)
	l.Printf("antes de fechar")
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 100 {
				l.Printf("concorrente")
			}
		}()
	}
	close(start)
	l.Close()
	wg.Wait()
	l.Close()
	l.Printf("depois de fechar")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "antes de fechar\n") || strings.Contains(string(b), "depois de fechar") {
		t.Fatalf("Close lost queued lines or accepted late writes: %q", b)
	}
}

func TestFileLogRotationFailurePreservesActiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aionwg.log")
	original := strings.Repeat("x", fileLogMax-1) + "\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".1", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path+".1", "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := openFileLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Printf("sem espaco para rotacao")
	l.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != original {
		t.Fatal("failed rotation must preserve the active file without exceeding its limit")
	}
}

func TestFormatHealthIsEmptyWhenNothingChanged(t *testing.T) {
	s := healthSample{HandshakeAgeSec: 12, Flows: 3, CapturedPkts: 100}
	if got := formatHealth(s, s); got != "" {
		t.Fatalf("an unchanged state must not be logged, got %q", got)
	}
}

// What betrays a drop is a counter that stops rising or one that jumps, so the
// line must show the change since the last sample, not the running total.
func TestFormatHealthShowsDeltasNotTotals(t *testing.T) {
	prev := healthSample{HandshakeAgeSec: 10, CapturedPkts: 1000, InjectedPkts: 900, InjectErr: 2}
	cur := healthSample{HandshakeAgeSec: 15, CapturedPkts: 1250, InjectedPkts: 900, InjectErr: 9, PingTunnelMs: 48, PingLossPct: 5, Flows: 4}
	got := formatHealth(cur, prev)
	for _, want := range []string{
		"handshake=15s", "ping=48ms", "perda=5%", "fluxos=4",
		"entrou+250", // 1250-1000
		"voltou+0",   // answers stopped coming back: the symptom of a dead path
		"erro_inj+7", // 9-2
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "espelho=") {
		t.Errorf("mirror fields must be absent when the mirror is off: %q", got)
	}
}

// After a reconnect the engine's counters restart from zero; a negative or
// wrapped delta would be nonsense in the log.
func TestFormatHealthHandlesCounterReset(t *testing.T) {
	got := formatHealth(healthSample{CapturedPkts: 5}, healthSample{CapturedPkts: 5000})
	if !strings.Contains(got, "entrou+5") {
		t.Fatalf("a reset counter must show its new value, got %q", got)
	}
}

func TestFormatHealthMirrorFieldsAndNeverHandshake(t *testing.T) {
	got := formatHealth(
		healthSample{HandshakeAgeSec: -1, MirrorOn: true, MirrorFlows: 12, MeterPackets: 300, MeterRingFull: 4},
		healthSample{HandshakeAgeSec: -1, MirrorOn: true, MeterPackets: 100})
	for _, want := range []string{"handshake=nunca", "espelho=12_fluxos", "meter+200", "meter_cheio+4"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestFormatHealthShowsGamePingThroughTunnelAndDirect(t *testing.T) {
	got := formatHealth(healthSample{HandshakeAgeSec: 5, PingGameMs: 36, PingGameDirectMs: 13}, healthSample{})
	if !strings.Contains(got, " jogo=36ms direto=13ms custo_tunel=+23ms") {
		t.Fatalf("both game pings and their difference must be logged: %q", got)
	}
	if got := formatHealth(healthSample{HandshakeAgeSec: 5, PingGameDirectMs: 13}, healthSample{}); !strings.Contains(got, "jogo=0ms direto=13ms") || strings.Contains(got, "custo_tunel") {
		t.Fatalf("no cost without both measurements: %q", got)
	}
	if got := formatHealth(healthSample{HandshakeAgeSec: 5}, healthSample{}); strings.Contains(got, "direto=") {
		t.Fatalf("no game fields before any game ping: %q", got)
	}
}
