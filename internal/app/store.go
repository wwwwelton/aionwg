package app

// Imported configs and settings live in %APPDATA%\AionWG.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Settings struct {
	Processes        []string      `json:"processes"`
	ProcessRules     []ProcessRule `json:"process_rules,omitempty"`
	PingTarget       string        `json:"ping_target"` // empty = auto (gateway of the tunnel subnet)
	LastConfig       string        `json:"last_config"`
	Version          int           `json:"version"`
	Mirror           bool          `json:"mirror"`
	MirrorNoLoopback bool          `json:"mirror_no_loopback"`      // skip the 127.0.0.1 TCP replay; the AionWG-Meter feed stays on
	UDPDuplicate     bool          `json:"udp_duplicate"`           // optional tunnel UDP clone; default OFF
	UDPOriginals     int           `json:"udp_originals"`           // A of A:B: every A originals release UDPCopies copies, 1..8
	UDPCopies        int           `json:"udp_copies"`              // B of A:B: copies per group, 1..8
	UDPForce         bool          `json:"udp_force"`               // duplicate even game UDP outside AllowedIPs, except LAN/DNS
	UDPNewestOut     bool          `json:"udp_newest_out"`          // opt-in LIFO scheduling of primary game UDP outbound
	UDPNewestIn      bool          `json:"udp_newest_in"`           // opt-in LIFO scheduling of primary game UDP inbound
	NoDNS            bool          `json:"no_dns_tunnel"`           // full tunnel: keep Windows' own DNS
	FullTunnel       bool          `json:"full_tunnel"`             // tunnel the whole system, not just the game // copy the game's TCP streams to 127.0.0.1 for DPS meters
	WFP              bool          `json:"wfp"`                     // WFP mode: tunnel only WFPApps, ignoring the port and full-tunnel modes
	WFPApps          []string      `json:"wfp_apps"`                // executables picked for WFP mode; kept apart from Processes so toggling WFP never loses either list
	BestEndpoint     bool          `json:"best_endpoint"`           // monitor faster endpoints while connected
	WarpMultipath    bool          `json:"warp_multipath"`          // WARP: open three extra sessions; default OFF
	CWBSearch        bool          `json:"cwb_search"`              // measure cwb* endpoints in idle rounds and switch to the lowest ping
	ProbeConfig      string        `json:"probe_config,omitempty"`  // name of the .conf copied to probe.conf: the free WARP account that tests endpoints for [b]
	CustomRelays     []string      `json:"custom_relays,omitempty"` // host:port endpoints measured as configured relays
}

func parseProcessRules(value string) ([]ProcessRule, []string, error) {
	var rules []ProcessRule
	var tunnel []string
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, policy := raw, ProcessPolicy(PolicyTunnel)
		if i := strings.IndexByte(raw, '='); i >= 0 {
			name = strings.TrimSpace(raw[:i])
			policy = ProcessPolicy(strings.ToUpper(strings.TrimSpace(raw[i+1:])))
		}
		if name == "" || !validProcessPolicy(policy) {
			return nil, nil, fmt.Errorf("regra inválida %q; use nome[=TUNNEL|BYPASS|BLOCK|DEFAULT]", raw)
		}
		rules = append(rules, ProcessRule{Name: name, Policy: policy})
		if policy == PolicyTunnel {
			tunnel = append(tunnel, name)
		}
	}
	return rules, tunnel, nil
}

func formatProcessRules(s Settings) string {
	if len(s.ProcessRules) == 0 {
		return strings.Join(s.Processes, ", ")
	}
	parts := make([]string, 0, len(s.ProcessRules))
	for _, rule := range s.ProcessRules {
		if rule.Policy == PolicyTunnel {
			parts = append(parts, rule.Name)
		} else {
			parts = append(parts, rule.Name+"="+string(rule.Policy))
		}
	}
	return strings.Join(parts, ", ")
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

const settingsVersion = 3

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
	s.UDPOriginals = normalizeUDPCopies(s.UDPOriginals)
	if s.Version < 3 { // v3: A:B ratio replaces the udp_batch flag (X:X = A=B=X)
		var old struct {
			UDPBatch bool `json:"udp_batch"`
		}
		if err == nil && json.Unmarshal(b, &old) == nil && old.UDPBatch {
			s.UDPOriginals = s.UDPCopies
		}
	}
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
	s.UDPOriginals = normalizeUDPCopies(s.UDPOriginals)
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(appDir(), "settings.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(appDir(), "settings.json"))
}

type ConfigType string

const (
	ConfigTypeWireGuard ConfigType = "wireguard"
	ConfigTypePingless  ConfigType = "pingless"
)

type ConfigMeta struct {
	Type ConfigType `json:"type"`
}

func metaPath(name string) string {
	return filepath.Join(configDir(), name+".meta.json")
}

func DetectConfigType(name string) ConfigType {
	if b, err := os.ReadFile(metaPath(name)); err == nil {
		var m ConfigMeta
		if err := json.Unmarshal(b, &m); err == nil && m.Type != "" {
			return m.Type
		}
	}
	if strings.HasSuffix(strings.ToLower(name), ".toml") {
		return ConfigTypePingless
	}
	b, err := os.ReadFile(filepath.Join(configDir(), name))
	if err == nil {
		text := string(b)
		if IsPinglessConfig(text) {
			return ConfigTypePingless
		}
	}
	return ConfigTypeWireGuard
}

func saveConfigMeta(name string, t ConfigType) {
	m := ConfigMeta{Type: t}
	b, _ := json.Marshal(m)
	_ = os.WriteFile(metaPath(name), b, 0o600)
}

func listConfigs() []string {
	ents, _ := os.ReadDir(configDir())
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if (ext == ".conf" || ext == ".toml") && !strings.HasSuffix(e.Name(), ".meta.json") {
				out = append(out, e.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}

// importConfig validates and copies a config into the app folder.
func importConfig(path string, forcedType ...ConfigType) (string, error) {
	path = strings.Trim(strings.TrimSpace(path), "\"'& ")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := string(b)
	targetType := ConfigTypeWireGuard
	if len(forcedType) > 0 && forcedType[0] != "" {
		targetType = forcedType[0]
	} else if IsPinglessConfig(text) || strings.HasSuffix(strings.ToLower(path), ".toml") {
		targetType = ConfigTypePingless
	}

	if targetType == ConfigTypePingless {
		if _, err := ParsePinglessConfig(text); err != nil {
			return "", fmt.Errorf("config Pingless inválida: %w", err)
		}
	} else {
		if _, err := ParseConfig(text); err != nil {
			return "", fmt.Errorf("config WireGuard inválida: %w", err)
		}
	}

	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return "", err
	}
	name := filepath.Base(path)
	ext := filepath.Ext(name)
	if targetType == ConfigTypePingless {
		if !strings.EqualFold(ext, ".toml") && !strings.EqualFold(ext, ".conf") {
			name += ".toml"
		}
	} else {
		if !strings.EqualFold(ext, ".conf") {
			name += ".conf"
		}
	}

	f, err := os.OpenFile(filepath.Join(configDir(), name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("já existe uma config chamada %s; remova-a ([d]) ou renomeie o arquivo", name)
	}
	if err != nil {
		return "", err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	saveConfigMeta(name, targetType)
	return name, nil
}

func readConfig(name string) (*WGConf, error) {
	b, err := os.ReadFile(filepath.Join(configDir(), name))
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(b))
}

func readPinglessConfig(name string) (*PinglessConfig, error) {
	b, err := os.ReadFile(filepath.Join(configDir(), name))
	if err != nil {
		return nil, err
	}
	return ParsePinglessConfig(string(b))
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
	game := RenderOfficial(string(raw), fmt.Sprintf("só AION 2 + Steam (%d IPs vistos pelo AionWG)", len(observed)),
		GameAllowed(c, observed, endpoints), false)
	if err := os.WriteFile(filepath.Join(dir, base+"-sistema.conf"), []byte(full), 0o600); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, base+"-jogo.conf"), []byte(game), 0o600); err != nil {
		return "", 0, err
	}
	return dir, len(observed), nil
}

func deleteConfig(name string) error {
	_ = os.Remove(metaPath(name))
	return os.Remove(filepath.Join(configDir(), name))
}
