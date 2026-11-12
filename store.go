package main

// Imported configs and settings live in %APPDATA%\AionWG.

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Settings struct {
	Processes    []string `json:"processes"`
	PingTarget   string   `json:"ping_target"` // empty = auto (gateway of the tunnel subnet)
	LastConfig   string   `json:"last_config"`
	Version      int      `json:"version"`
	Mirror       bool     `json:"mirror"`
	UDPDuplicate bool     `json:"udp_duplicate"`  // optional direct UDP clone; default OFF
	UDPCopies    int      `json:"udp_copies"`     // extra copies per game UDP datagram, 1..8
	UDPForce     bool     `json:"udp_force"`      // duplicate even game UDP outside AllowedIPs, except LAN/DNS
	UDPNewestOut bool     `json:"udp_newest_out"` // opt-in LIFO scheduling of primary game UDP outbound
	UDPNewestIn  bool     `json:"udp_newest_in"`  // opt-in LIFO scheduling of primary game UDP inbound
	NoDNS        bool     `json:"no_dns_tunnel"`  // full tunnel: keep Windows' own DNS
	FullTunnel   bool     `json:"full_tunnel"`    // tunnel the whole system, not just the game // copy the game's TCP streams to 127.0.0.1 for DPS meters
}

// Default AION 2 executable names. Check Task Manager → Details if the
// game uses another name and edit the list with [p] in the app.
var defaultProcesses = []string{
	"Aion2.exe",
	"Aion2-Win64-Shipping.exe",
	"AION2-Win64-Shipping.exe",
	"steam.exe",
	"steamwebhelper.exe",
}

// steamProcesses are added to existing lists by the v2 settings migration.
var steamProcesses = []string{"steam.exe", "steamwebhelper.exe"}

const settingsVersion = 2

func hasProcess(list []string, name string) bool {
	for _, p := range list {
		if strings.EqualFold(strings.TrimSpace(p), name) {
			return true
		}
	}
	return false
}

func appDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, "AionWG")
}

func configDir() string { return filepath.Join(appDir(), "configs") }

func loadSettings() Settings {
	s := Settings{Processes: defaultProcesses}
	b, err := os.ReadFile(filepath.Join(appDir(), "settings.json"))
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if len(s.Processes) == 0 {
		s.Processes = defaultProcesses
	}
	s.UDPCopies = normalizeUDPCopies(s.UDPCopies)
	if s.Version < 2 { // v2: Steam joins the tunnel
		for _, p := range steamProcesses {
			if !hasProcess(s.Processes, p) {
				s.Processes = append(s.Processes, p)
			}
		}
	}
	if s.Version != settingsVersion {
		s.Version = settingsVersion
		_ = saveSettings(s)
	}
	return s
}

func saveSettings(s Settings) error {
	if err := os.MkdirAll(appDir(), 0o700); err != nil {
		return err
	}
	s.Version = settingsVersion
	s.UDPCopies = normalizeUDPCopies(s.UDPCopies)
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(filepath.Join(appDir(), "settings.json"), b, 0o600)
}

func listConfigs() []string {
	ents, _ := os.ReadDir(configDir())
	var out []string
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".conf") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// importConfig validates and copies a .conf into the app folder.
func importConfig(path string) (string, error) {
	path = strings.Trim(strings.TrimSpace(path), "\"'& ")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if _, err := ParseConfig(string(b)); err != nil {
		return "", fmt.Errorf("config inválida: %w", err)
	}
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return "", err
	}
	name := filepath.Base(path)
	if !strings.EqualFold(filepath.Ext(name), ".conf") {
		name += ".conf"
	}
	if err := os.WriteFile(filepath.Join(configDir(), name), b, 0o600); err != nil {
		return "", err
	}
	return name, nil
}

func readConfig(name string) (*WGConf, error) {
	b, err := os.ReadFile(filepath.Join(configDir(), name))
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(b))
}

// exportOfficial writes configs for the official WireGuard client next to
// the .exe and returns the folder.
func exportOfficial(name string, observed, endpoints []netip.Addr) (string, int, error) {
	raw, err := os.ReadFile(filepath.Join(configDir(), name))
	if err != nil {
		return "", 0, err
	}
	c, err := ParseConfig(string(raw))
	if err != nil {
		return "", 0, err
	}
	dir := filepath.Join(appDir(), "oficial")
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Join(filepath.Dir(exe), "configs-wireguard-oficial")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	full := RenderOfficial(string(raw), "sistema inteiro (rede local fora do túnel)", FullTunnelAllowed(c, endpoints), true)
	game := RenderOfficial(string(raw), fmt.Sprintf("só AION 2 + Steam (faixas NCSOFT/Valve + %d IPs vistos)", len(observed)),
		GameAllowed(c, observed, endpoints), false)
	if err := os.WriteFile(filepath.Join(dir, base+"-sistema.conf"), []byte(full), 0o600); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, base+"-jogo.conf"), []byte(game), 0o600); err != nil {
		return "", 0, err
	}
	return dir, len(observed), nil
}

func deleteConfig(name string) error { return os.Remove(filepath.Join(configDir(), name)) }
