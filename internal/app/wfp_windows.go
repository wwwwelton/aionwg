//go:build windows

package app

// WFP mode, Windows side: a WinDivert SOCKET layer handle (backed by the
// Windows Filtering Platform ALE layers) reports the PID of every bind/connect
// before the first packet exists. The capture path still runs on the NETWORK
// layer, which carries no PID, so this only answers "who owns this local port".

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpFallbackTTL bounds how long one system-table dump answers for every port.
const wfpFallbackTTL = 2 * time.Second

// wfpMonitor owns the SOCKET handle and the process tree for one engine.
type wfpMonitor struct {
	table  *wfpTable
	h      divertHandle
	logf   func(string, ...any)
	stop   chan struct{}
	wg     sync.WaitGroup
	procMu sync.Mutex

	fbMu    sync.Mutex        // guards only the cache below, never held during a dump
	fbPorts map[portKey]uint8 // ports of selected apps, from the system table
	fbAt    time.Time
	fbGen   uint64                                   // bumped by invalidateFallback; a dump begun earlier is not published
	dumpMu  sync.Mutex                               // single-flight: one dump at a time
	dump    func(map[uint32]uint8) map[portKey]uint8 // nil = system table; tests inject
}

// startWFPMonitor always returns a working monitor: the process tree refresh and
// the system-table fallback need no driver. The SOCKET layer handle is optional;
// when it cannot be opened (driver blocked...) the error is logged and every
// port is answered from the system table instead. The handle is sniff-only and
// receive-only (mandatory for this layer), so it can never block or delay a
// socket operation: a stuck AionWG cannot freeze the apps it watches.
func startWFPMonitor(table *wfpTable, logf func(string, ...any)) *wfpMonitor {
	m := &wfpMonitor{table: table, logf: logf, stop: make(chan struct{})}
	m.refreshProcesses()
	m.wg.Add(1)
	go m.processLoop()
	h, err := divertOpen(fmt.Sprintf("processId != %d", windows.GetCurrentProcessId()), divertLayerSocket, 0, divertFlagSniff|divertFlagRecvOnly)
	if err != nil {
		logf("aviso: WFP sem camada SOCKET (%v) — usando a tabela do sistema", err)
		return m
	}
	m.h = h
	m.wg.Add(1)
	go m.eventLoop()
	return m
}

// systemClass returns the class of the selected app that the system TCP/UDP
// table says owns the port (classNone if none). It serves sockets the SOCKET
// layer never saw (opened before its handle). One dump answers every port for
// wfpFallbackTTL, so a burst of packets does not dump the table per packet.
func (m *wfpMonitor) systemClass(proto uint8, port uint16) uint8 {
	k := portKey{proto, port}
	if ports, ok := m.fallbackCache(); ok {
		return ports[k]
	}
	m.dumpMu.Lock()
	defer m.dumpMu.Unlock()
	if ports, ok := m.fallbackCache(); ok { // the dump we waited for already published
		return ports[k]
	}
	m.fbMu.Lock()
	gen := m.fbGen
	m.fbMu.Unlock()
	var ports map[portKey]uint8
	if m.dump != nil {
		ports = m.dump(m.table.SelectedPIDs())
	} else {
		ports, _ = dumpOwnedPorts(m.table.SelectedPIDs())
	}
	m.fbMu.Lock()
	if gen == m.fbGen { // selection changed meanwhile: answer this caller, cache nothing stale
		m.fbPorts, m.fbAt = ports, time.Now()
	}
	m.fbMu.Unlock()
	return ports[k] // zero value is classNone
}

func (m *wfpMonitor) fallbackCache() (map[portKey]uint8, bool) {
	m.fbMu.Lock()
	defer m.fbMu.Unlock()
	return m.fbPorts, m.fbPorts != nil && time.Since(m.fbAt) <= wfpFallbackTTL
}

// invalidateFallback drops the cached system-table answer, so a changed app
// selection applies to the next packet instead of after wfpFallbackTTL.
func (m *wfpMonitor) invalidateFallback() {
	m.fbMu.Lock()
	m.fbPorts = nil
	m.fbGen++
	m.fbMu.Unlock()
}

func (m *wfpMonitor) eventLoop() {
	defer m.wg.Done()
	var addr divertAddress
	for {
		if err := m.h.recvEvent(&addr); err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			// A persistent error must not spin a CPU core.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		raw := (*[wdAddrSize]byte)(unsafe.Pointer(&addr))[:]
		if ev, ok := decodeSocketEvent(raw); ok {
			m.table.mu.Lock()
			_, known := m.table.procs[ev.pid]
			m.table.mu.Unlock()
			if !known && ev.event != wdEventSocketClose {
				m.refreshProcesses()
			}
			m.table.Apply(ev, time.Now())
		}
	}
}

func (m *wfpMonitor) processLoop() {
	defer m.wg.Done()
	tk := time.NewTicker(2 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-tk.C:
			m.refreshProcesses()
		}
	}
}

func (m *wfpMonitor) refreshProcesses() {
	m.procMu.Lock()
	defer m.procMu.Unlock()
	if procs := snapshotProcesses(); procs != nil {
		m.table.SetProcesses(procs)
	}
}

// Close stops the goroutines and releases the handle, if one was opened.
func (m *wfpMonitor) Close() {
	close(m.stop)
	if m.h != 0 {
		m.h.shutdown()
	}
	m.wg.Wait()
	if m.h != 0 {
		m.h.close()
	}
}

// snapshotProcesses returns pid -> {lower-case exe, parent pid}, or nil if the
// snapshot failed (callers keep the previous tree).
func snapshotProcesses() map[uint32]wfpProc {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	out := map[uint32]wfpProc{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out[pe.ProcessID] = wfpProc{
			name: strings.ToLower(windows.UTF16ToString(pe.ExeFile[:])),
			ppid: pe.ParentProcessID,
		}
	}
	return out
}
