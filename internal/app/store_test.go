package app

import (
	"os"
	"path/filepath"
	"strings"
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

func TestImportConfigNeverOverwrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("APPDATA", home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("HOME", home)
	src := filepath.Join(t.TempDir(), "profile.conf")
	write := func(addr string) {
		t.Helper()
		conf := strings.Replace(sampleConf, "10.66.66.2/24", addr, 1)
		if err := os.WriteFile(src, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("10.66.66.2/24")
	if _, err := importConfig(src); err != nil {
		t.Fatal(err)
	}
	write("10.66.66.9/24")
	if _, err := importConfig(src); err == nil {
		t.Fatal("second import with the same name must fail")
	}
	c, err := readConfig("profile.conf")
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := c.Addr(false); a.String() != "10.66.66.2" {
		t.Fatalf("original profile was overwritten: %v", a)
	}
	if got := listConfigs(); len(got) != 1 {
		t.Fatalf("configs: %v", got)
	}
}

// Settings written before WFP existed must load with WFP off and no apps, and
// the WFP fields must survive a save/load without touching the port-based list.
func TestSettingsWFPDefaultsAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	if err := os.MkdirAll(appDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	old := `{"processes":["Aion2.exe","steam.exe","steamwebhelper.exe"],"version":2,"full_tunnel":true}`
	if err := os.WriteFile(filepath.Join(appDir(), "settings.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s := loadSettings()
	if s.WFP || len(s.WFPApps) != 0 {
		t.Fatalf("old settings must load with WFP off and no apps: %+v", s)
	}

	s.WFP, s.WFPApps = true, []string{"Discord.exe", "chrome.exe"}
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	got := loadSettings()
	if !got.WFP || len(got.WFPApps) != 2 || got.WFPApps[0] != "Discord.exe" || got.WFPApps[1] != "chrome.exe" {
		t.Fatalf("WFP fields lost: %+v", got)
	}
	if !got.FullTunnel || len(got.Processes) != 3 {
		t.Fatalf("enabling WFP must not change the port/system settings: %+v", got)
	}
}

func TestProcessRulesPersist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	s := Settings{
		Processes:    []string{"Aion2.exe"},
		ProcessRules: []ProcessRule{{Name: "Aion2.exe", Policy: PolicyTunnel}, {Name: "Discord.exe", Policy: PolicyBypass}},
	}
	if err := saveSettings(s); err != nil {
		t.Fatal(err)
	}
	got := loadSettings()
	if len(got.ProcessRules) != 2 || got.ProcessRules[1].Policy != PolicyBypass {
		t.Fatalf("process rules lost: %+v", got.ProcessRules)
	}
}
