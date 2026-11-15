package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type TunnelProfile struct {
	Name       string
	Protocol   string
	Endpoint   string
	Addresses  []string
	DNS        []string
	AllowedIPs []string
	MTU        int
	Keepalive  int
	Valid      bool
	Validation string
}

type TunnelManager struct {
	dir string
}

func NewTunnelManager(dir string) TunnelManager { return TunnelManager{dir: dir} }

func (m TunnelManager) Profile(name string) (TunnelProfile, error) {
	name, err := profileFilename(name)
	if err != nil {
		return TunnelProfile{}, err
	}
	raw, err := os.ReadFile(filepath.Join(m.dir, name))
	if err != nil {
		return TunnelProfile{}, err
	}
	profile := TunnelProfile{Name: name}
	conf, err := ParseConfig(string(raw))
	if err != nil {
		profile.Validation = err.Error()
		return profile, err
	}
	profile.Valid = true
	profile.Protocol = "WireGuard/UDP"
	profile.MTU = conf.MTU
	for _, address := range conf.Addresses {
		profile.Addresses = append(profile.Addresses, address.String())
	}
	for _, dns := range conf.DNS {
		profile.DNS = append(profile.DNS, dns.String())
	}
	for _, peer := range conf.Peers {
		profile.Endpoint = peer.Endpoint
		profile.Keepalive = peer.Keepalive
		for _, allowed := range peer.AllowedIPs {
			profile.AllowedIPs = append(profile.AllowedIPs, allowed.String())
		}
	}
	return profile, nil
}

func (m TunnelManager) Profiles() ([]TunnelProfile, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	profiles := make([]TunnelProfile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".conf") {
			continue
		}
		profile, err := m.Profile(entry.Name())
		if err != nil {
			profile.Name = entry.Name()
		}
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return strings.ToLower(profiles[i].Name) < strings.ToLower(profiles[j].Name) })
	return profiles, nil
}

func (m TunnelManager) Duplicate(source, destination string) error {
	source, err := profileFilename(source)
	if err != nil {
		return err
	}
	destination, err = profileFilename(destination)
	if err != nil {
		return err
	}
	if source == destination {
		return fmt.Errorf("o perfil de destino precisa ser diferente")
	}
	raw, err := os.ReadFile(filepath.Join(m.dir, source))
	if err != nil {
		return err
	}
	if _, err := ParseConfig(string(raw)); err != nil {
		return fmt.Errorf("perfil de origem inválido: %w", err)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(m.dir, destination)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (m TunnelManager) Rename(source, destination string) error {
	source, err := profileFilename(source)
	if err != nil {
		return err
	}
	destination, err = profileFilename(destination)
	if err != nil {
		return err
	}
	if source == destination {
		return fmt.Errorf("o perfil de destino precisa ser diferente")
	}
	if _, err := m.Profile(source); err != nil {
		return fmt.Errorf("perfil de origem inválido: %w", err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, destination)); err == nil {
		return fmt.Errorf("o perfil %s já existe", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(filepath.Join(m.dir, source), filepath.Join(m.dir, destination))
}

func (m TunnelManager) Delete(name string) error {
	name, err := profileFilename(name)
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(m.dir, name))
}

func profileFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("nome de perfil vazio")
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("nome de perfil inválido")
	}
	if !strings.EqualFold(filepath.Ext(name), ".conf") {
		name += ".conf"
	}
	if filepath.Base(name) != name || name == ".conf" {
		return "", fmt.Errorf("nome de perfil inválido")
	}
	return name, nil
}

func joinProfileValues(values []string) string { return strings.Join(values, ", ") }
