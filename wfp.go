package main

// Portable core of the WFP mode: which sockets belong to the apps the user
// picked. The Windows side (wfp_windows.go) feeds it with WinDivert SOCKET
// layer events, which carry the PID when the socket is bound/connected, before
// the first packet exists. That removes the delay of the TCP/UDP table the
// default mode relies on.

import (
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

// wfpTable maps a local port to the PID that owns it and answers whether that
// PID belongs to a selected app (or descends from one).
type wfpTable struct {
	mu     sync.Mutex
	ports  map[portKey]wfpPort
	apps   map[string]struct{} // lower-case exe names the user picked
	procs  map[uint32]wfpProc  // live process tree, refreshed by the caller
	tunnel map[uint32]bool     // memoised: pid -> goes through the tunnel
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
		tunnel: map[uint32]bool{},
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
	t.tunnel = map[uint32]bool{}
	t.mu.Unlock()
}

// SetProcesses replaces the live process tree used to follow child processes.
func (t *wfpTable) SetProcesses(procs map[uint32]wfpProc) {
	t.mu.Lock()
	t.procs = procs
	t.tunnel = map[uint32]bool{}
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
	return t.selectedLocked(pid, 0)
}

// wfpMaxDepth bounds the parent walk: Windows PIDs are reused, so a stale ppid
// can form a cycle.
const wfpMaxDepth = 32

func (t *wfpTable) selectedLocked(pid uint32, depth int) bool {
	if v, ok := t.tunnel[pid]; ok {
		return v
	}
	if depth > wfpMaxDepth {
		return false
	}
	p, ok := t.procs[pid]
	if !ok {
		return false
	}
	v := false
	if _, hit := t.apps[p.name]; hit {
		v = true
	} else if p.ppid != 0 && p.ppid != pid {
		v = t.selectedLocked(p.ppid, depth+1)
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
	if t.Selected(pid) {
		return classGame, true
	}
	return classNone, true
}
