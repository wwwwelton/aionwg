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
