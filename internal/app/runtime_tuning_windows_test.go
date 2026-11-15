//go:build windows

package app

import (
	"runtime/debug"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRuntimeTuning(t *testing.T) {
	priority, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	gc := debug.SetGCPercent(-1)
	limit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(gc)
		debug.SetMemoryLimit(limit)
		if err := windows.SetPriorityClass(windows.CurrentProcess(), priority); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("GOMEMLIMIT", "")
	if err := tuneRuntime(); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetGCPercent(400); got != 400 {
		t.Fatalf("GC=%d", got)
	}
	if got := debug.SetMemoryLimit(-1); got <= 0 || got > 512<<20 {
		t.Fatalf("memory limit=%d", got)
	}
	if got, err := windows.GetPriorityClass(windows.CurrentProcess()); err != nil || got != windows.HIGH_PRIORITY_CLASS {
		t.Fatalf("priority=%d err=%v", got, err)
	}
	t.Setenv("GOMEMLIMIT", "128MiB")
	debug.SetMemoryLimit(128 << 20)
	if err := tuneRuntime(); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != 128<<20 {
		t.Fatalf("explicit memory limit overwritten: %d", got)
	}
}
