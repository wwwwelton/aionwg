//go:build windows && embedded

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEmbeddedStandaloneSmoke(t *testing.T) {
	if err := prepareRuntime(); err != nil {
		t.Fatal(err)
	}
	h, err := divertOpen("false", divertLayerNetwork, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err := wintunDLL.Load(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		handle  uintptr
		name    string
		payload []byte
	}{
		{divertDLL.Handle(), "WinDivert.dll", embeddedDivert},
		{wintunDLL.Handle(), "wintun.dll", embeddedWintun},
	} {
		var filename [32768]uint16
		if _, err := windows.GetModuleFileName(windows.Handle(entry.handle), &filename[0], uint32(len(filename))); err != nil {
			t.Fatal(err)
		}
		path := windows.UTF16ToString(filename[:])
		if !strings.Contains(strings.ToLower(path), `\program files\aionwg-runtime\`) {
			t.Fatalf("loaded external dependency: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, entry.payload) {
			t.Fatalf("loaded DLL differs from embedded data: %s (%v)", path, err)
		}
		if entry.name == "WinDivert.dll" {
			driver, err := os.ReadFile(filepath.Join(filepath.Dir(path), "WinDivert64.sys"))
			if err != nil || !bytes.Equal(driver, embeddedDriver) {
				t.Fatal("embedded driver missing or modified", err)
			}
		}
		t.Log("loaded verified embedded dependency:", path)
	}
}
