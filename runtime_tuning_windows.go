//go:build windows

package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/windows"
)

func tuneRuntime() error {
	// MEMORYSTATUSEX; leave at least three quarters of available RAM outside Go.
	var memory struct {
		Length, Load                                       uint32
		TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
		TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
	}
	memory.Length = uint32(unsafe.Sizeof(memory))
	if os.Getenv("GOMEMLIMIT") == "" {
		proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
		if ok, _, err := proc.Call(uintptr(unsafe.Pointer(&memory))); ok == 0 {
			return fmt.Errorf("GlobalMemoryStatusEx: %w", err)
		}
		debug.SetMemoryLimit(int64(min(memory.AvailPhys/4, 512<<20)))
	}
	debug.SetGCPercent(400)
	if err := windows.SetPriorityClass(windows.CurrentProcess(), windows.HIGH_PRIORITY_CLASS); err != nil {
		return fmt.Errorf("HIGH_PRIORITY_CLASS: %w", err)
	}
	return nil
}
