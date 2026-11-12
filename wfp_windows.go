//go:build windows

package main

// WFP mode, Windows side: a WinDivert SOCKET layer handle (backed by the
// Windows Filtering Platform ALE layers) reports the PID of every bind/connect
// before the first packet exists. The capture path still runs on the NETWORK
// layer, which carries no PID, so this only answers "who owns this local port".

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wfpMonitor owns the SOCKET handle and the process tree for one engine.
type wfpMonitor struct {
	table *wfpTable
	h     divertHandle
	logf  func(string, ...any)
	stop  chan struct{}
	wg    sync.WaitGroup
}

// startWFPMonitor opens the SOCKET layer. It is sniff-only and receive-only
// (mandatory for this layer): it can never block or delay a socket operation,
// so a stuck AionWG cannot freeze the apps it watches.
func startWFPMonitor(table *wfpTable, logf func(string, ...any)) (*wfpMonitor, error) {
	h, err := divertOpen("true", divertLayerSocket, 0, divertFlagSniff|divertFlagRecvOnly)
	if err != nil {
		return nil, err
	}
	m := &wfpMonitor{table: table, h: h, logf: logf, stop: make(chan struct{})}
	m.refreshProcesses()
	m.wg.Add(2)
	go m.eventLoop()
	go m.processLoop()
	return m, nil
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
	if procs := snapshotProcesses(); procs != nil {
		m.table.SetProcesses(procs)
	}
}

// Close stops both goroutines and releases the handle.
func (m *wfpMonitor) Close() {
	close(m.stop)
	m.h.shutdown()
	m.wg.Wait()
	m.h.close()
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
