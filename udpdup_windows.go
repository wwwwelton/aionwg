//go:build windows

package main

import (
	"runtime"

	"golang.org/x/sys/windows"
)

// runUDPDuplicateWorker pins the secondary path to a dedicated OS thread
// and lowers its scheduling priority so it cannot preempt the main packet
// capture workers under normal scheduling conditions.
// This is best-effort only: CPU and uplink are still shared resources.
func (e *Engine) runUDPDuplicateWorker() {
	defer e.wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	kernel := windows.NewLazySystemDLL("kernel32.dll")
	thread, _, _ := kernel.NewProc("GetCurrentThread").Call()
	if thread != 0 {
		// THREAD_PRIORITY_BELOW_NORMAL = -1. Restore NORMAL before the Go
		// runtime is allowed to reuse this OS thread for other goroutines.
		setPriority := kernel.NewProc("SetThreadPriority")
		if changed, _, _ := setPriority.Call(thread, ^uintptr(0)); changed != 0 {
			defer setPriority.Call(thread, 0)
		}
	}

	e.udpDup.run(e.stop, func(pkt []byte, t dupTarget) error {
		if e.closing.Load() {
			return windows.ERROR_OPERATION_ABORTED
		}
		if t.tunnel {
			// Same SNAT'd packet as the original, through WireGuard (a fresh
			// transport counter each, so the peer accepts both). pkt is shared
			// between jobs, so the tunnel gets its own copy.
			e.tun.inject(clonePktBuf(pkt))
			return nil
		}
		// Direct copy keeps its original Windows IP/source port and goes through
		// Windows' ordinary outbound route (WinDivert ignores IfIdx for outbound).
		return e.h.send(pkt, &t.addr)
	})
}

// dupTarget says where a duplicate goes: through the tunnel (pkt is the SNAT'd
// tunnel packet) or straight out via Windows (pkt is the original, addr its capture).
type dupTarget struct {
	addr   divertAddress
	tunnel bool
}
