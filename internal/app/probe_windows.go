//go:build windows

package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// probeConfFn picks the identity used to handshake-test candidate endpoints;
// tests replace it.
var probeConfFn = savedProbeConf

// probeConfPath is the private copy of the .conf chosen for [b] (a free WARP
// account). It is not a tunnel profile and never appears in the profile list.
func probeConfPath() string { return filepath.Join(appDir(), "probe.conf") }

// probeUsable accepts any file for the same server key (same WARP network),
// including the same file as the live profile: the user may choose it and no
// error is shown. A file for another server could never handshake here.
func probeUsable(live, c *WGConf) bool {
	return live != nil && c != nil && len(live.Peers) > 0 && len(c.Peers) > 0 &&
		bytes.Equal(c.Peers[0].PublicKey, live.Peers[0].PublicKey)
}

// probeConf is the identity for endpoint tests (the private copy of the file
// chosen for [b]), or nil when none is usable right now. Cloudflare WARP drops
// the live session when the same key handshakes from a second socket (observed:
// ~20 s of 85% loss), so on WARP the live key is not used while the game runs;
// other servers accept several connections per key.
func (e *Engine) probeConf() *WGConf {
	c := probeConfFn(e.conf)
	if c != nil && bytes.Equal(c.PrivateKey, e.conf.PrivateKey) && e.gameServer().IsValid() &&
		len(warpSeeds(e.eps()[0].Addr())) > 0 {
		return nil
	}
	return c
}

// savedProbeConf returns the chosen probe file, or nil when none was chosen or
// it is for another server.
func savedProbeConf(live *WGConf) *WGConf {
	b, err := os.ReadFile(probeConfPath())
	if err != nil {
		return nil
	}
	c, err := ParseConfig(string(b))
	if err != nil || !probeUsable(live, c) {
		return nil
	}
	return c
}

// setProbeConfig validates the .conf at path against the live profile (when
// known) and stores a private copy. It returns the file name for display.
func setProbeConfig(path string, live *WGConf) (string, error) {
	path = strings.Trim(strings.TrimSpace(path), "\"'& ")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	c, err := ParseConfig(string(b))
	if err != nil {
		return "", fmt.Errorf("config inválida: %w", err)
	}
	if live != nil && !probeUsable(live, c) {
		return "", errors.New("precisa ser uma config do mesmo servidor do perfil em uso (mesma chave pública do peer)")
	}
	if err := os.MkdirAll(appDir(), 0o700); err != nil {
		return "", err
	}
	tmp := probeConfPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, probeConfPath()); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return filepath.Base(path), nil
}

// liveConf is the profile in use, or the last one used when disconnected.
func (m *model) liveConf() *WGConf {
	if m.eng != nil {
		return m.eng.conf
	}
	if c, err := readConfig(m.settings.LastConfig); err == nil {
		return c
	}
	return nil
}

// beginProbeInput asks for the .conf of the free account used by [b].
func (m *model) beginProbeInput() {
	m.mode = modeProbeFile
	m.input.SetValue("")
	m.input.Placeholder = `C:\Users\voce\Downloads\conta-gratuita.conf (vazio remove)`
	m.input.Focus()
}

// applyProbeInput stores (or, when empty, removes) the probe account.
func (m *model) applyProbeInput(v string) {
	if strings.TrimSpace(v) == "" {
		_ = os.Remove(probeConfPath())
		m.settings.ProbeConfig = ""
		_ = saveSettings(m.settings)
		m.log("Conta de teste do [b] removida (só testa endpoints com o jogo parado)")
		return
	}
	name, err := setProbeConfig(v, m.liveConf())
	if err != nil {
		m.log("ERRO na conta de teste do [b]: %v", err)
		return
	}
	m.settings.ProbeConfig = name
	_ = saveSettings(m.settings)
	m.log("Conta de teste do [b]: %s (a config principal continua a do programa)", name)
}
