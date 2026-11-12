package main

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestTable() *wfpTable {
	t := newWFPTable()
	t.SetApps([]string{"Game.exe"})
	t.SetProcesses(map[uint32]wfpProc{
		10: {name: "game.exe", ppid: 1},
		11: {name: "browser.exe", ppid: 10}, // child of the game
		12: {name: "helper.exe", ppid: 11},  // grandchild
		20: {name: "other.exe", ppid: 1},    // unrelated
		30: {name: "loop-a.exe", ppid: 31},  // PID reuse can create cycles
		31: {name: "loop-b.exe", ppid: 30},
	})
	return t
}

func TestWFPClassFollowsSelectedAppsAndChildren(t *testing.T) {
	tb := newTestTable()
	tb.Bind(protoTCP, 5000, 10, t0)
	tb.Bind(protoTCP, 5001, 11, t0)
	tb.Bind(protoUDP, 5002, 12, t0)
	tb.Bind(protoTCP, 5003, 20, t0)

	for _, c := range []struct {
		proto uint8
		port  uint16
		want  uint8
		known bool
	}{
		{protoTCP, 5000, classGame, true},  // selected app (name compare is case-insensitive)
		{protoTCP, 5001, classGame, true},  // child follows
		{protoUDP, 5002, classGame, true},  // grandchild follows
		{protoTCP, 5003, classNone, true},  // known, not selected
		{protoTCP, 9999, classNone, false}, // unknown: caller must fall back
		{protoUDP, 5000, classNone, false}, // TCP and UDP ports are distinct keys
	} {
		got, known := tb.Class(c.proto, c.port, t0)
		if got != c.want || known != c.known {
			t.Errorf("proto %d port %d: got (%d,%v), want (%d,%v)", c.proto, c.port, got, known, c.want, c.known)
		}
	}
}

func TestWFPPIDCycleDoesNotHang(t *testing.T) {
	tb := newTestTable()
	if tb.Selected(30) || tb.Selected(31) {
		t.Fatal("a parent cycle with no selected app must not be selected")
	}
}

// A new socket may reuse a port before the old socket's CLOSE is processed.
func TestWFPCloseDoesNotEvictNewOwner(t *testing.T) {
	tb := newTestTable()
	tb.Bind(protoTCP, 6000, 20, t0)
	tb.Bind(protoTCP, 6000, 10, t0) // port reused by the game
	tb.Close(protoTCP, 6000, 20)    // late CLOSE of the previous owner
	if c, known := tb.Class(protoTCP, 6000, t0); c != classGame || !known {
		t.Fatalf("new owner evicted: (%d,%v)", c, known)
	}
	tb.Close(protoTCP, 6000, 10)
	if _, known := tb.Class(protoTCP, 6000, t0); known {
		t.Fatal("port must be forgotten after its owner closes")
	}
}

// CLOSE events are lost for sockets closed before the handle opened, so entries
// must expire instead of growing forever or labelling a reused port wrongly.
func TestWFPEntriesExpire(t *testing.T) {
	tb := newTestTable()
	tb.Bind(protoTCP, 7000, 10, t0)
	if _, known := tb.Class(protoTCP, 7000, t0.Add(wfpPortTTL-time.Second)); !known {
		t.Fatal("entry expired too early")
	}
	if _, known := tb.Class(protoTCP, 7000, t0.Add(wfpPortTTL+time.Second)); known {
		t.Fatal("entry must expire")
	}
	if len(tb.ports) != 0 {
		t.Fatal("expired entry must be removed")
	}
}

// Changing the selection must take effect without a reconnect.
func TestWFPSetAppsInvalidatesDecision(t *testing.T) {
	tb := newTestTable()
	tb.Bind(protoTCP, 8000, 20, t0)
	if c, _ := tb.Class(protoTCP, 8000, t0); c != classNone {
		t.Fatal("other.exe is not selected yet")
	}
	tb.SetApps([]string{"other.exe"})
	if c, _ := tb.Class(protoTCP, 8000, t0); c != classGame {
		t.Fatal("selection change was not applied")
	}
	tb.SetApps(nil)
	if c, _ := tb.Class(protoTCP, 8000, t0); c != classNone {
		t.Fatal("empty selection must tunnel nothing")
	}
}

// sockAddr builds a WINDIVERT_ADDRESS the way the driver lays it out
// (windivert.h): Timestamp(8) Layer(1) Event(1) flags(2) Reserved2(4), then the
// Socket union: EndpointId(8) ParentEndpointId(8) ProcessId(4) LocalAddr(16)
// RemoteAddr(16) LocalPort(2) RemotePort(2) Protocol(1).
func sockAddr(event uint8, pid uint32, port uint16, proto uint8) []byte {
	b := make([]byte, wdAddrSize)
	b[8], b[9] = 3, event // Layer = SOCKET
	le32 := func(o int, v uint32) {
		b[o], b[o+1], b[o+2], b[o+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	le32(16, 0xAAAAAAAA) // EndpointId (must not be mistaken for the PID)
	le32(24, 0xBBBBBBBB) // ParentEndpointId
	le32(32, pid)
	b[32+4+16+16], b[32+4+16+16+1] = byte(port), byte(port>>8)
	b[32+4+16+16+4] = proto
	return b
}

func TestDecodeSocketEvent(t *testing.T) {
	ev, ok := decodeSocketEvent(sockAddr(wdEventSocketConnect, 4242, 51000, protoTCP))
	if !ok || ev.pid != 4242 || ev.port != 51000 || ev.proto != protoTCP || ev.event != wdEventSocketConnect {
		t.Fatalf("got %+v ok=%v", ev, ok)
	}
	ev, ok = decodeSocketEvent(sockAddr(wdEventSocketBind, 7, 65535, protoUDP))
	if !ok || ev.pid != 7 || ev.port != 65535 || ev.proto != protoUDP {
		t.Fatalf("udp bind: %+v ok=%v", ev, ok)
	}
}

func TestDecodeSocketEventIgnoresWhatItCannotTrust(t *testing.T) {
	for name, raw := range map[string][]byte{
		"short buffer":   make([]byte, wdAddrSize-1),
		"listen event":   sockAddr(5, 1, 80, protoTCP),
		"accept event":   sockAddr(6, 1, 80, protoTCP),
		"network packet": sockAddr(0, 1, 80, protoTCP),
		"icmp protocol":  sockAddr(wdEventSocketConnect, 1, 80, 1),
		"port zero":      sockAddr(wdEventSocketConnect, 1, 0, protoTCP),
		"pid zero":       sockAddr(wdEventSocketConnect, 0, 80, protoTCP),
	} {
		if _, ok := decodeSocketEvent(raw); ok {
			t.Errorf("%s: must be ignored", name)
		}
	}
}

func TestWFPApplyBindThenClose(t *testing.T) {
	tb := newTestTable()
	conn, _ := decodeSocketEvent(sockAddr(wdEventSocketConnect, 11, 52000, protoTCP))
	tb.Apply(conn, t0)
	if c, known := tb.Class(protoTCP, 52000, t0); c != classGame || !known {
		t.Fatalf("child of the game not tunnelled: (%d,%v)", c, known)
	}
	cl, _ := decodeSocketEvent(sockAddr(wdEventSocketClose, 11, 52000, protoTCP))
	tb.Apply(cl, t0)
	if _, known := tb.Class(protoTCP, 52000, t0); known {
		t.Fatal("CLOSE must forget the port")
	}
}

func TestWFPDecideUsesFallbackOnlyWhenSocketLayerHasNoRecord(t *testing.T) {
	tb := newTestTable()
	calls := 0
	yes := func() bool { calls++; return true }
	no := func() bool { calls++; return false }

	// Known to the SOCKET layer: the fallback must not be asked, and a known
	// non-selected owner must not be overridden by the system table.
	tb.Bind(protoTCP, 9000, 20, t0)
	if got := tb.Decide(protoTCP, 9000, t0, yes); got != classNone || calls != 0 {
		t.Fatalf("known owner overridden: class=%d calls=%d", got, calls)
	}
	tb.Bind(protoTCP, 9001, 10, t0)
	if got := tb.Decide(protoTCP, 9001, t0, no); got != classGame || calls != 0 {
		t.Fatalf("known selected owner lost: class=%d calls=%d", got, calls)
	}

	// Unknown (socket opened before the handle): the system table decides.
	if got := tb.Decide(protoTCP, 9100, t0, yes); got != classGame {
		t.Fatalf("fallback hit ignored: %d", got)
	}
	if got := tb.Decide(protoTCP, 9100, t0, no); got != classNone {
		t.Fatalf("fallback miss captured: %d", got)
	}
	if got := tb.Decide(protoTCP, 9100, t0, nil); got != classNone {
		t.Fatalf("nil fallback must capture nothing: %d", got)
	}
}

func TestWFPSelectedPIDsListsAppsAndDescendantsOnly(t *testing.T) {
	got := newTestTable().SelectedPIDs()
	for _, pid := range []uint32{10, 11, 12} {
		if got[pid] != classGame {
			t.Errorf("pid %d must be selected", pid)
		}
	}
	for _, pid := range []uint32{1, 20, 30, 31} {
		if _, ok := got[pid]; ok {
			t.Errorf("pid %d must not be selected", pid)
		}
	}
}

// The user's requirement: with WFP on, neither the port-based process list nor
// the full-system tunnel decides anything; only the selected apps do.
func TestResolveClassWFPReplacesPortAndSystemModes(t *testing.T) {
	port := func(c uint8) func() uint8 { return func() uint8 { return c } }
	wfp := func(c uint8) func() uint8 { return func() uint8 { return c } }

	for _, c := range []struct {
		name      string
		on        bool
		portClass uint8
		full      bool
		wfpClass  uint8
		wantClass uint8
		wantFull  bool
	}{
		// WFP off: port-based mode and full tunnel behave exactly as before.
		{"off, listed process", false, classGame, false, classNone, classGame, false},
		{"off, not listed", false, classNone, false, classGame, classNone, false},
		{"off, full tunnel", false, classNone, true, classNone, classNone, true},

		// WFP on: only the selected apps count.
		{"on, selected app", true, classNone, false, classGame, classGame, false},
		{"on, not selected", true, classNone, false, classNone, classNone, false},
		{"on, port-listed but not selected", true, classGame, false, classNone, classNone, false},
		{"on, full tunnel requested is ignored", true, classNone, true, classNone, classNone, false},
		{"on, full tunnel ignored, app still tunnelled", true, classNone, true, classGame, classGame, false},

		// AionWG's own traffic (self-test) must keep using the tunnel.
		{"on, self-test", true, classSelf, true, classNone, classSelf, false},
	} {
		gotClass, gotFull := resolveClass(c.on, port(c.portClass), c.full, wfp(c.wfpClass))
		if gotClass != c.wantClass || gotFull != c.wantFull {
			t.Errorf("%s: got (class %d, full %v), want (class %d, full %v)",
				c.name, gotClass, gotFull, c.wantClass, c.wantFull)
		}
	}
}

// With WFP off the selected-app decision must never be evaluated: it can dump
// the system table, which the default mode must not pay for.
func TestResolveClassOffNeverRunsWFPDecision(t *testing.T) {
	resolveClass(false,
		func() uint8 { return classNone }, false,
		func() uint8 { t.Fatal("WFP decision evaluated while WFP is off"); return classNone })
}

func TestBuildAppList(t *testing.T) {
	got := buildAppList(
		[]string{"chrome.exe", "Discord.exe", "AionWG.exe", "", "  ", "CHROME.EXE", "notepad.exe"},
		[]string{"discord.exe", "Gone.exe"}, // Gone.exe is selected but no longer running
		"aionwg.exe")

	want := []appEntry{
		{"Discord.exe", true, true},  // selected first; the live spelling wins over the stored one
		{"Gone.exe", true, false},    // selected but closed: must stay listed
		{"chrome.exe", false, true},  // "CHROME.EXE" does not create a duplicate
		{"notepad.exe", false, true}, // AionWG itself and blank names are never offered
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d: got %+v, want %+v (all: %+v)", i, got[i], want[i], got)
		}
	}
}

func TestToggleAppIsCaseInsensitiveAndDoesNotMutate(t *testing.T) {
	orig := []string{"Discord.exe", "chrome.exe"}
	snapshot := append([]string(nil), orig...)

	removed := toggleApp(orig, "DISCORD.EXE")
	if len(removed) != 1 || removed[0] != "chrome.exe" {
		t.Fatalf("remove: %v", removed)
	}
	added := toggleApp(orig, " notepad.exe ")
	if len(added) != 3 || added[2] != "notepad.exe" {
		t.Fatalf("add (must trim): %v", added)
	}
	if got := toggleApp(orig, "  "); len(got) != 2 {
		t.Fatalf("blank name must not be added: %v", got)
	}
	for i := range orig {
		if orig[i] != snapshot[i] || len(orig) != len(snapshot) {
			t.Fatalf("input was mutated: %v", orig)
		}
	}
}

// The picker list shrinks as processes exit; a stale cursor would make the
// next keypress act on nothing.
func TestClampCursor(t *testing.T) {
	for _, c := range []struct{ cursor, n, want int }{
		{0, 0, 0},   // empty list
		{5, 0, 0},   // stale cursor, list emptied
		{-1, 3, 0},  // never negative
		{2, 3, 2},   // in range is untouched
		{3, 3, 2},   // one past the end
		{40, 10, 9}, // list shrank a lot
	} {
		if got := clampCursor(c.cursor, c.n); got != c.want {
			t.Errorf("clampCursor(%d,%d) = %d, want %d", c.cursor, c.n, got, c.want)
		}
	}
}
