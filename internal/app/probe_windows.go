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

// A handshake with the live key from a second socket makes the server drop or
// redirect the live session (observed: ~20 s of 85% loss), so a test is only
// isolated with a different identity on the same server. Nothing is chosen or
// created automatically.
func probeUsable(live, c *WGConf) bool {
	return live != nil && c != nil && len(live.Peers) > 0 && len(c.Peers) > 0 &&
		!bytes.Equal(c.PrivateKey, live.PrivateKey) &&
		bytes.Equal(c.Peers[0].PublicKey, live.Peers[0].PublicKey)
}

// savedProbeConf returns the chosen probe identity, or nil when none was chosen
// or it cannot work with the live profile.
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
		return "", errors.New("precisa ser OUTRA conta WARP (chave privada diferente) no mesmo servidor do perfil em uso")
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
