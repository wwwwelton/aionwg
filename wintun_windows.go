//go:build windows

package main

// "AionWG-Meter": a Wintun network adapter that only exists so that Npcap
// (and the DPS meters built on it) can see the game's traffic in plaintext.
//
// Every game packet (both directions, original addresses, already decrypted)
// is copied into the adapter as a received packet. Npcap captures it there;
// Windows itself discards it (the destination is not an address of that
// adapter), so the real connection is untouched.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wintunDLL        = windows.NewLazyDLL("wintun.dll")
	procWtCreate     = wintunDLL.NewProc("WintunCreateAdapter")
	procWtOpen       = wintunDLL.NewProc("WintunOpenAdapter")
	procWtClose      = wintunDLL.NewProc("WintunCloseAdapter")
	procWtStart      = wintunDLL.NewProc("WintunStartSession")
	procWtEnd        = wintunDLL.NewProc("WintunEndSession")
	procWtAllocSend  = wintunDLL.NewProc("WintunAllocateSendPacket")
	procWtSend       = wintunDLL.NewProc("WintunSendPacket")
	meterAdapterName = "AionWG-Meter"
	meterAdapterGUID = windows.GUID{Data1: 0x41494f4e, Data2: 0x5747, Data3: 0x4d74, Data4: [8]byte{0x8a, 0x1e, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x01}}
	errNoWintun      = errors.New("wintun.dll não encontrado ao lado do AionWG.exe")
)

type meterAdapter struct {
	mu      sync.Mutex
	adapter uintptr
	session uintptr
	closed  atomic.Bool
	written atomic.Uint64
	full    atomic.Uint64
	latSum  atomic.Int64 // ns spent in write() (incl. waiting for mu) since the last takeLatency
	latMax  atomic.Int64
	latN    atomic.Uint64
}

func openMeterAdapter() (*meterAdapter, error) {
	if err := wintunDLL.Load(); err != nil {
		return nil, errNoWintun
	}
	name, _ := windows.UTF16PtrFromString(meterAdapterName)
	ttype, _ := windows.UTF16PtrFromString("AionWG")
	// reuse the adapter from a previous run if it is still there
	a, _, _ := procWtOpen.Call(uintptr(unsafe.Pointer(name)))
	if a == 0 {
		var err error
		a, _, err = procWtCreate.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(ttype)),
			uintptr(unsafe.Pointer(&meterAdapterGUID)))
		if a == 0 {
			return nil, fmt.Errorf("criando adaptador %s: %v", meterAdapterName, err)
		}
	}
	s, _, err := procWtStart.Call(a, 0x400000) // 4 MiB ring
	if s == 0 {
		procWtClose.Call(a)
		return nil, fmt.Errorf("iniciando sessão Wintun: %v", err)
	}
	return &meterAdapter{adapter: a, session: s}, nil
}

// write copies one IP packet into the adapter (as if it had been received).
func (m *meterAdapter) write(pkt []byte) {
	if m == nil || m.closed.Load() || len(pkt) == 0 {
		return
	}
	start := time.Now()
	defer func() {
		d := int64(time.Since(start))
		m.latSum.Add(d)
		m.latN.Add(1)
		for old := m.latMax.Load(); d > old && !m.latMax.CompareAndSwap(old, d); old = m.latMax.Load() {
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed.Load() {
		return
	}
	p, _, _ := procWtAllocSend.Call(m.session, uintptr(len(pkt)))
	if p == 0 {
		m.full.Add(1) // ring full: the meter is not keeping up, skip
		return
	}
	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&p)) // ring memory owned by wintun.dll
	copy(unsafe.Slice((*byte)(ptr), len(pkt)), pkt)
	procWtSend.Call(m.session, p)
	m.written.Add(1)
}

// takeLatency returns the average and maximum write() time since the last call.
func (m *meterAdapter) takeLatency() (avg, max time.Duration, n uint64) {
	if m == nil {
		return
	}
	n = m.latN.Swap(0)
	sum, mx := m.latSum.Swap(0), m.latMax.Swap(0)
	if n > 0 {
		avg = time.Duration(sum / int64(n))
	}
	return avg, time.Duration(mx), n
}

func (m *meterAdapter) Close() {
	if m == nil || !m.closed.CompareAndSwap(false, true) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	procWtEnd.Call(m.session)
	procWtClose.Call(m.adapter)
}
