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

	e.udpDup.run(e.stop, func(pkt []byte, addr divertAddress) error {
		if e.closing.Load() {
			return windows.ERROR_OPERATION_ABORTED
		}
		// Packet retains its original Windows IP/source port. This injects
		// through Windows' ordinary outbound route; WinDivert ignores IfIdx
		// for outbound injection (it does NOT choose a dedicated NIC).
		// The WireGuard original is already queued before this copy.
		return e.h.send(pkt, &addr)
	})
}
