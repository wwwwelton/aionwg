//go:build windows && !external

package main

import (
	_ "embed"
	"path/filepath"

	"aionwg/internal/runtimefiles"
	"golang.org/x/sys/windows"
)

//go:embed WinDivert.dll
var embeddedDivert []byte

//go:embed WinDivert64.sys
var embeddedDriver []byte

//go:embed wintun.dll
var embeddedWintun []byte

//go:embed shugo-compat.dll
var embeddedCompat []byte

// compatPath is the Shugo compatibility DLL loaded by the [m] relay.
var compatPath string

func prepareRuntime() error {
	if err := ensureCertTrusted(); err != nil {
		return err
	}
	dir, err := runtimefiles.Prepare([]runtimefiles.File{
		{Name: "WinDivert.dll", Data: embeddedDivert},
		{Name: "WinDivert64.sys", Data: embeddedDriver},
		{Name: "wintun.dll", Data: embeddedWintun},
		{Name: "shugo-compat.dll", Data: embeddedCompat},
	})
	if err != nil {
		return err
	}
	compatPath = filepath.Join(dir, "shugo-compat.dll")
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if _, err = windows.AddDllDirectory(path); err != nil {
		return err
	}
	// Ignore unrelated DLLs beside the EXE; dependencies come from the verified bundle or Windows.
	return windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_USER_DIRS | windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
}
