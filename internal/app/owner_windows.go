//go:build windows

package app

// Figures out which local TCP/UDP ports belong to which listed process.

import (
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

type ownerEntry struct {
	class   uint8
	expires time.Time
}

type procMeta struct {
	name  string
	class uint8
	child bool // started by the game (shop/browser), tunnelled as classApp
}

type ownerTracker struct {
	mu          sync.Mutex
	refreshMu   sync.Mutex
	names       map[string]uint8 // lower-case exe names the user picked
	paths       map[string]uint8 // normalized executable paths
	pids        map[uint32]procMeta
	cache       map[portKey]ownerEntry
	lastRefresh time.Time
	selfPID     uint32
	dumps       uint64
	stop        chan struct{}
}

func newOwnerTracker(names []string) *ownerTracker {
	t := &ownerTracker{
		pids:    map[uint32]procMeta{},
		paths:   map[string]uint8{},
		cache:   map[portKey]ownerEntry{},
		selfPID: uint32(os.Getpid()),
		stop:    make(chan struct{}),
	}
	t.SetNames(names)
	go t.loop()
	return t
}

func (t *ownerTracker) SetNames(names []string) {
	t.SetRules(nil, names)
}

func (t *ownerTracker) SetRules(rules []ProcessRule, names []string) {
	m := map[string]uint8{}
	p := map[string]uint8{}
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			m[n] = classOfName(n)
		}
	}
	for _, rule := range rules {
		name := strings.ToLower(strings.TrimSpace(rule.Name))
		path := cleanProcessPath(rule.Path)
		if (name == "" && path == "") || !validProcessPolicy(rule.Policy) {
			continue
		}
		policy := ProcessPolicy(strings.ToUpper(strings.TrimSpace(string(rule.Policy))))
		if policy == PolicyDefault {
			continue
		}
		class := processPolicyClass(policy, name)
		if name != "" {
			m[name] = class
		}
		if path != "" {
			p[path] = class
		}
	}
	t.mu.Lock()
	t.names = m
	t.paths = p
	t.cache = map[portKey]ownerEntry{}
	t.mu.Unlock()
	t.scanProcesses()
}

func (t *ownerTracker) Close() { close(t.stop) }

func (t *ownerTracker) loop() {
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tk.C:
			t.scanProcesses()
			t.mu.Lock()
			now := time.Now()
			for k, e := range t.cache {
				if now.After(e.expires) {
					delete(t.cache, k)
				}
			}
			t.mu.Unlock()
		}
	}
}

// Processes returns the currently matched listed processes.
func (t *ownerTracker) Processes() []ProcInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ProcInfo, 0, len(t.pids))
	for pid, m := range t.pids {
		out = append(out, ProcInfo{pid, m.name})
	}
	return out
}

// Dumps returns how many connection-table dumps were done (diagnostics).
func (t *ownerTracker) Dumps() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dumps
}

func (t *ownerTracker) scanProcesses() {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	t.mu.Lock()
	names := t.names
	paths := t.paths
	t.mu.Unlock()
	found := map[uint32]procMeta{}
	type proc struct {
		pid, ppid uint32
		name      string
	}
	var all []proc
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		name := windows.UTF16ToString(pe.ExeFile[:])
		all = append(all, proc{pe.ProcessID, pe.ParentProcessID, name})
		class, ok := names[strings.ToLower(name)]
		if len(paths) > 0 {
			if path := processExecutablePath(pe.ProcessID); path != "" {
				if pathClass, pathOK := paths[cleanProcessPath(path)]; pathOK {
					class, ok = pathClass, true
				}
			}
		}
		if ok {
			found[pe.ProcessID] = procMeta{name: name, class: class}
		}
	}
	// Child processes of the game (in-game shop / web browser such as
	// UnrealCEFSubProcess.exe, crash reporter…) go through the tunnel too,
	// otherwise the shop talks to the server from a different IP.
	for changed := true; changed; {
		changed = false
		for _, p := range all {
			if _, ok := found[p.pid]; ok || p.pid == 0 || p.pid == p.ppid {
				continue
			}
			if parent, ok := found[p.ppid]; ok && (parent.class == classGame || parent.class == classBlock || parent.child) {
				childClass := classApp
				if parent.class == classBlock {
					childClass = classBlock
				}
				found[p.pid] = procMeta{name: p.name, class: childClass, child: true}
				changed = true
			}
		}
	}
	t.mu.Lock()
	changed := len(found) != len(t.pids)
	for pid := range found {
		if _, ok := t.pids[pid]; !ok {
			changed = true
		}
	}
	t.pids = found
	if changed {
		t.cache = map[portKey]ownerEntry{}
	}
	t.mu.Unlock()
}

// Class reports which kind of listed process owns the local port.
func (t *ownerTracker) Class(proto uint8, port uint16) uint8 {
	k := portKey{proto, port}
	now := time.Now()
	t.mu.Lock()
	if e, ok := t.cache[k]; ok && now.Before(e.expires) {
		t.mu.Unlock()
		return e.class
	}
	t.mu.Unlock()

	// Coalesce concurrent lookups: one table dump serves everyone waiting.
	t.refreshMu.Lock()
	defer t.refreshMu.Unlock()
	t.mu.Lock()
	if t.lastRefresh.After(now) {
		if e, ok := t.cache[k]; ok {
			t.mu.Unlock()
			return e.class
		}
	}
	pids := make(map[uint32]uint8, len(t.pids)+1)
	for p, m := range t.pids {
		pids[p] = m.class
	}
	pids[t.selfPID] = classSelf
	t.dumps++
	t.mu.Unlock()

	owned, all := dumpOwnedPorts(pids)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastRefresh = time.Now()
	// one dump answers for every socket on the machine
	for ap := range all {
		if _, mine := owned[ap]; !mine {
			t.cache[ap] = ownerEntry{classNone, t.lastRefresh.Add(2 * time.Second)}
		}
	}
	for ok, c := range owned {
		t.cache[ok] = ownerEntry{c, t.lastRefresh.Add(30 * time.Second)}
	}
	if c, ok := owned[k]; ok {
		return c
	}
	t.cache[k] = ownerEntry{classNone, t.lastRefresh.Add(1500 * time.Millisecond)}
	return classNone
}

// ListAllProcesses returns unique exe names of running processes.
func ListAllProcesses() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	seen := map[string]bool{}
	var out []string
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		n := windows.UTF16ToString(pe.ExeFile[:])
		if !seen[strings.ToLower(n)] {
			seen[strings.ToLower(n)] = true
			out = append(out, n)
		}
	}
	return out
}

func getTable(proc *windows.LazyProc, family, class uint32) []byte {
	size := uint32(64 * 1024)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), uintptr(class), 0)
		if r == 0 {
			return buf[:size]
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
		size += 4096
	}
	return nil
}

func ntohsDword(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func dumpOwnedPorts(pids map[uint32]uint8) (map[portKey]uint8, map[portKey]struct{}) {
	out := map[portKey]uint8{}
	all := map[portKey]struct{}{}
	le := binary.LittleEndian
	scan := func(tbl []byte, rowSize, portOff, pidOff int, proto uint8) {
		if len(tbl) < 4 {
			return
		}
		n := int(le.Uint32(tbl))
		for i := 0; i < n; i++ {
			off := 4 + i*rowSize
			if off+rowSize > len(tbl) {
				break
			}
			row := tbl[off : off+rowSize]
			k := portKey{proto, ntohsDword(row[portOff:])}
			all[k] = struct{}{}
			if c, ok := pids[le.Uint32(row[pidOff:])]; ok {
				out[k] = c
			}
		}
	}
	// MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid (24 bytes)
	scan(getTable(procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPidAll), 24, 8, 20, protoTCP)
	// MIB_TCP6ROW_OWNER_PID: laddr[16], scope, lport, raddr[16], scope, rport, state, pid (56 bytes)
	scan(getTable(procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPidAll), 56, 20, 52, protoTCP)
	// MIB_UDPROW_OWNER_PID: laddr, lport, pid (12 bytes)
	scan(getTable(procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPid), 12, 4, 8, protoUDP)
	// MIB_UDP6ROW_OWNER_PID: laddr[16], scope, lport, pid (28 bytes)
	scan(getTable(procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPid), 28, 20, 24, protoUDP)
	return out, all
}
