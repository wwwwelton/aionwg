package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSteamMigration(t *testing.T) {
	dir := t.TempDir()
	// os.UserConfigDir uses APPDATA on Windows and XDG_CONFIG_HOME on Linux.
	// All three must be redirected, otherwise a Windows test can access and
	// overwrite the real %APPDATA%\AionWG\settings.json.
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	settingsDir := filepath.Join(dir, "AionWG")
	if got := appDir(); got != settingsDir {
		t.Fatalf("settings directory not isolated: got %q, want %q", got, settingsDir)
	}
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(settingsDir, "settings.json"),
		[]byte(`{"processes":["Aion2.exe","MeuJogo.exe"],"last_config":"wg01.conf"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := loadSettings()
	want := []string{"Aion2.exe", "MeuJogo.exe", "steam.exe", "steamwebhelper.exe"}
	if len(s.Processes) != len(want) {
		t.Fatalf("%v", s.Processes)
	}
	for i := range want {
		if s.Processes[i] != want[i] {
			t.Fatalf("%v", s.Processes)
		}
	}
	// user removes steam later: must not come back
	s.Processes = []string{"Aion2.exe"}
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	if got := loadSettings().Processes; len(got) != 1 {
		t.Fatalf("steam re-added: %v", got)
	}
}
