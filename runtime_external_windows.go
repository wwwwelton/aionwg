//go:build windows && !embedded

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// compatPath is the Shugo compatibility DLL loaded by the [m] relay.
var compatPath string

func prepareRuntime() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	compatPath = filepath.Join(filepath.Dir(exe), "shugo-compat.dll")
	return windows.SetDllDirectory(filepath.Dir(exe))
}
