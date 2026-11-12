package main

// Portable core of the WFP mode: which sockets belong to the apps the user
// picked. The Windows side (wfp_windows.go) feeds it with WinDivert SOCKET
// layer events, which carry the PID when the socket is bound/connected, before
// the first packet exists. That removes the delay of the TCP/UDP table the
// default mode relies on.

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Port owner classes.
const (
	classNone uint8 = iota // not in the list
	classGame              // AION 2 (and anything listed that is not Steam)
	classApp               // Steam (tunnelled, but not mirrored / not "the game")
	classSelf              // AionWG itself (self-test traffic)
)

func classOfName(lower string) uint8 {
	if strings.HasPrefix(lower, "steam") {
		return classApp
	}
	return classGame
}

type portKey struct {
	proto uint8
	port  uint16
}

// ProcInfo is a matched running process.
type ProcInfo struct {
	PID  uint32
	Name string
}

// wfpTable maps a local port to the PID that owns it and answers whether that
// PID belongs to a selected app (or descends from one).
type wfpTable struct {
	mu     sync.Mutex
	ports  map[portKey]wfpPort
	apps   map[string]struct{} // lower-case exe names the user picked
	procs  map[uint32]wfpProc  // live process tree, refreshed by the caller
	tunnel map[uint32]uint8    // memoised: pid -> class of its selected app (classNone = not tunnelled)
}

type wfpPort struct {
	pid     uint32
	expires time.Time
}

type wfpProc struct {
	name string // lower-case exe name
	ppid uint32
}

// wfpPortTTL bounds entries whose CLOSE event was missed (the layer cannot see
// sockets closed before the handle was opened, nor events dropped under load).
const wfpPortTTL = 10 * time.Minute

func newWFPTable() *wfpTable {
	return &wfpTable{
		ports:  map[portKey]wfpPort{},
		apps:   map[string]struct{}{},
		procs:  map[uint32]wfpProc{},
		tunnel: map[uint32]uint8{},
	}
}

// SetApps replaces the selected executables (case-insensitive).
func (t *wfpTable) SetApps(names []string) {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			m[n] = struct{}{}
		}
	}
	t.mu.Lock()
	t.apps = m
	t.tunnel = map[uint32]uint8{}
	t.mu.Unlock()
}

// SetProcesses replaces the live process tree used to follow child processes.
func (t *wfpTable) SetProcesses(procs map[uint32]wfpProc) {
	t.mu.Lock()
	t.procs = procs
	t.tunnel = map[uint32]uint8{}
	t.mu.Unlock()
}

// Bind records that pid owns the local port.
func (t *wfpTable) Bind(proto uint8, port uint16, pid uint32, now time.Time) {
	t.mu.Lock()
	t.ports[portKey{proto, port}] = wfpPort{pid, now.Add(wfpPortTTL)}
	t.mu.Unlock()
}

// Close forgets the port, but only if pid is still its owner: a new socket may
// have reused the port before this CLOSE event is processed.
func (t *wfpTable) Close(proto uint8, port uint16, pid uint32) {
	k := portKey{proto, port}
	t.mu.Lock()
	if p, ok := t.ports[k]; ok && p.pid == pid {
		delete(t.ports, k)
	}
	t.mu.Unlock()
}

// Owner returns the PID known for the port, if any and not expired.
func (t *wfpTable) Owner(proto uint8, port uint16, now time.Time) (uint32, bool) {
	k := portKey{proto, port}
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.ports[k]
	if !ok {
		return 0, false
	}
	if now.After(p.expires) {
		delete(t.ports, k)
		return 0, false
	}
	return p.pid, true
}

// Selected reports whether pid is a selected app, or a descendant of one.
func (t *wfpTable) Selected(pid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.classLocked(pid, 0) != classNone
}

// wfpMaxDepth bounds the parent walk: Windows PIDs are reused, so a stale ppid
// can form a cycle.
const wfpMaxDepth = 32

// wfpClassOfApp is the class a selected app gets. Only the game itself keeps
// the game treatment (DPS mirror, extra UDP, latest-first ordering, game ping);
// any other app is tunnelled without it, since those options were built for
// the game and can degrade apps such as voice chat or a browser.
func wfpClassOfApp(lowerName string) uint8 {
	if strings.HasPrefix(lowerName, "aion2") {
		return classGame
	}
	return classApp
}

// classLocked returns the class of the selected app pid belongs to: the app
// itself, or the nearest selected ancestor (so a child of the game inherits the
// game's class whatever its own name is). classNone means not tunnelled.
func (t *wfpTable) classLocked(pid uint32, depth int) uint8 {
	if v, ok := t.tunnel[pid]; ok {
		return v
	}
	if depth > wfpMaxDepth {
		return classNone
	}
	p, ok := t.procs[pid]
	if !ok {
		return classNone
	}
	v := classNone
	if _, hit := t.apps[p.name]; hit {
		v = wfpClassOfApp(p.name)
	} else if p.ppid != 0 && p.ppid != pid {
		v = t.classLocked(p.ppid, depth+1)
	}
	t.tunnel[pid] = v
	return v
}

// Class reports the owner class of a local port for the capture path. ok is
// false when WFP has no record of the port, so the caller falls back to the
// system table.
func (t *wfpTable) Class(proto uint8, port uint16, now time.Time) (class uint8, ok bool) {
	pid, found := t.Owner(proto, port, now)
	if !found {
		return classNone, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.classLocked(pid, 0), true
}

// WinDivert SOCKET layer events (windivert.h). Only the ones that name the
// owner of an outgoing port matter here.
const (
	wdEventSocketBind    = 3
	wdEventSocketConnect = 4
	wdEventSocketClose   = 7
)

// wdAddrSize is sizeof(WINDIVERT_ADDRESS); the layer data union starts at 16.
const (
	wdAddrSize     = 80
	wdAddrUnion    = 16
	wdSockPID      = wdAddrUnion + 16 // after EndpointId and ParentEndpointId
	wdSockLocalprt = wdSockPID + 4 + 16 + 16
	wdSockProto    = wdSockLocalprt + 4
)

// wfpEvent is one decoded SOCKET layer event.
type wfpEvent struct {
	event uint8
	pid   uint32
	port  uint16
	proto uint8
}

// decodeSocketEvent reads a raw WINDIVERT_ADDRESS. ok is false for events and
// protocols the table does not track, so unknown input is ignored, never fatal.
func decodeSocketEvent(raw []byte) (ev wfpEvent, ok bool) {
	if len(raw) < wdAddrSize {
		return ev, false
	}
	ev.event = raw[9] // Event:8 sits right after Layer:8 in the first bit-field
	switch ev.event {
	case wdEventSocketBind, wdEventSocketConnect, wdEventSocketClose:
	default:
		return ev, false
	}
	ev.pid = uint32(raw[wdSockPID]) | uint32(raw[wdSockPID+1])<<8 |
		uint32(raw[wdSockPID+2])<<16 | uint32(raw[wdSockPID+3])<<24
	ev.port = uint16(raw[wdSockLocalprt]) | uint16(raw[wdSockLocalprt+1])<<8
	ev.proto = raw[wdSockProto]
	if ev.proto != protoTCP && ev.proto != protoUDP || ev.port == 0 || ev.pid == 0 {
		return ev, false
	}
	return ev, true
}

// Apply updates the table from one event.
func (t *wfpTable) Apply(ev wfpEvent, now time.Time) {
	if ev.event == wdEventSocketClose {
		t.Close(ev.proto, ev.port, ev.pid)
		return
	}
	t.Bind(ev.proto, ev.port, ev.pid, now)
}

// Decide returns the owner class for a local port in WFP mode. The SOCKET
// layer cannot see sockets opened before its handle, so when it has no record
// the system table is asked instead (fallback). fallback returns the class of
// the selected app that owns the port (classNone if none does), so WFP mode
// never captures less than the default mode would for the same apps, never
// captures anything that is not selected, and gives a socket the same class
// whether the SOCKET layer or the system table identified it.
func (t *wfpTable) Decide(proto uint8, port uint16, now time.Time, fallback func() uint8) uint8 {
	if class, known := t.Class(proto, port, now); known {
		return class
	}
	if fallback != nil {
		return fallback()
	}
	return classNone
}

// SelectedPIDs returns the live PIDs of selected apps and their descendants
// with the class each one gets, in the shape dumpOwnedPorts expects.
func (t *wfpTable) SelectedPIDs() map[uint32]uint8 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[uint32]uint8{}
	for pid := range t.procs {
		if c := t.classLocked(pid, 0); c != classNone {
			out[pid] = c
		}
	}
	return out
}

// SelectedProcs lists the live selected processes (apps and descendants) with
// the executable name, for the status panel.
func (t *wfpTable) SelectedProcs() []ProcInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ProcInfo
	for pid, p := range t.procs {
		if t.classLocked(pid, 0) != classNone {
			out = append(out, ProcInfo{PID: pid, Name: p.name})
		}
	}
	return out
}

// resolveClass is the precedence rule between the three ways of deciding what
// to tunnel. It is the whole contract of WFP mode, kept free of Windows types
// so it can be tested anywhere:
//
//   - WFP off: the port-based mode, unchanged (listed processes, plus
//     everything when full is set).
//   - WFP on: only the selected apps; the full tunnel is ignored and the
//     port-based process list is not consulted. AionWG's own traffic
//     (self-test) is the one exception: it must keep using the tunnel to test it.
func resolveClass(
	wfpOn bool,
	portClass func() uint8, // listed-process owner class (port-based mode)
	full bool,
	wfpClass func() uint8, // selected-app decision
) (class uint8, fullTunnel bool) {
	if !wfpOn {
		return portClass(), full
	}
	if c := portClass(); c == classSelf {
		return c, false
	}
	return wfpClass(), false
}

// appEntry is one row of the WFP app picker.
type appEntry struct {
	Name     string // executable name, as Windows reports it
	Selected bool
	Running  bool // false: picked earlier but not running now
}

// buildAppList merges the running executables with the already selected ones.
// A selected app that is not running stays listed, otherwise closing it would
// silently drop it from the selection. self (AionWG's own executable) is never
// offered. Names compare case-insensitively and keep the spelling Windows
// reported. Selected apps come first, then alphabetical.
func buildAppList(running, selected []string, self string) []appEntry {
	self = strings.ToLower(self)
	byKey := map[string]*appEntry{}
	add := func(name string, isRunning, isSelected bool) {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if key == "" || key == self {
			return
		}
		e := byKey[key]
		if e == nil {
			e = &appEntry{Name: name}
			byKey[key] = e
		}
		if isRunning {
			if !e.Running {
				e.Name = name // the first live spelling replaces a stored one; later ones never flip it
			}
			e.Running = true
		}
		if isSelected {
			e.Selected = true
		}
	}
	for _, n := range selected {
		add(n, false, true)
	}
	for _, n := range running {
		add(n, true, false)
	}
	out := make([]appEntry, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// toggleApp returns a new selection with name added or removed. It never
// modifies selected: Settings lives in a Bubble Tea model that is copied by value.
func toggleApp(selected []string, name string) []string {
	key := strings.ToLower(strings.TrimSpace(name))
	out := make([]string, 0, len(selected)+1)
	removed := false
	for _, s := range selected {
		if strings.ToLower(strings.TrimSpace(s)) == key {
			removed = true
			continue
		}
		out = append(out, s)
	}
	if !removed && key != "" {
		out = append(out, strings.TrimSpace(name))
	}
	return out
}

// clampCursor keeps a list cursor inside [0, n-1] (0 for an empty list). The
// picker list changes under the cursor as processes start and exit, so the
// cursor must be re-limited whenever it is refreshed.
func clampCursor(cursor, n int) int {
	if n <= 0 || cursor < 0 {
		return 0
	}
	if cursor >= n {
		return n - 1
	}
	return cursor
}
