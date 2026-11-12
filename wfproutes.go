package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Only destinations already attributed to a selected process may reach ensure.
type wfpRoutes struct {
	mu     sync.Mutex
	saveMu sync.Mutex
	conf   *WGConf
	path   string
	paths  []string
	apply  func(string) error
	added  map[netip.Addr]bool
	saved  int
}

func (r *wfpRoutes) ensure(dst netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !dst.IsValid() || !dst.IsGlobalUnicast() || r.conf.Bypass(dst) || len(r.conf.Peers) == 0 {
		return fmt.Errorf("destino WFP ou peer inválido")
	}
	if r.conf.Allowed(dst) || r.added[dst] {
		return nil
	}
	prefix := netip.PrefixFrom(dst, dst.BitLen())
	// Unknown destinations use the first peer, matching official export policy.
	update := fmt.Sprintf("public_key=%s\nupdate_only=true\nallowed_ip=%s\n", hex.EncodeToString(r.conf.Peers[0].PublicKey), prefix)
	if err := r.apply(update); err != nil {
		return err
	}
	if r.added == nil {
		r.added = make(map[netip.Addr]bool)
	}
	r.added[dst] = true
	return nil
}

// Disk writes run from housekeeping, never from the packet path.
func (r *wfpRoutes) flush() error {
	if r == nil {
		return nil
	}
	r.saveMu.Lock()
	defer r.saveMu.Unlock()
	r.mu.Lock()
	if len(r.added) == r.saved {
		r.mu.Unlock()
		return nil
	}
	addrs := make([]netip.Addr, 0, len(r.added))
	for a := range r.added {
		addrs = append(addrs, a)
	}
	targets := append([]string{r.path}, r.paths...)
	r.mu.Unlock()
	var firstErr error
	for _, path := range targets {
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			if path != r.path && os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		c, err := ParseConfig(string(b))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if hex.EncodeToString(c.Peers[0].PublicKey) != hex.EncodeToString(r.conf.Peers[0].PublicKey) {
			if path != r.path {
				continue
			}
			return fmt.Errorf("peer do perfil mudou; destinos WFP não foram gravados")
		}
		var routes []string
		for _, a := range addrs {
			if !c.Allowed(a) {
				routes = append(routes, netip.PrefixFrom(a, a.BitLen()).String())
			}
		}
		if len(routes) == 0 {
			continue
		}
		sort.Strings(routes)
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			header, _, _ := strings.Cut(line, "#")
			if strings.EqualFold(strings.TrimSpace(header), "[Peer]") {
				lines[i] += "\nAllowedIPs = " + strings.Join(routes, ", ")
				break
			}
		}
		f, err := os.CreateTemp(filepath.Dir(path), ".wfp-*.tmp")
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := f.WriteString(strings.Join(lines, "\n")); err != nil {
			f.Close()
			os.Remove(f.Name())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(f.Name())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := f.Close(); err != nil {
			os.Remove(f.Name())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := os.Rename(f.Name(), path); err != nil {
			os.Remove(f.Name())
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	if firstErr != nil {
		return firstErr
	}
	r.mu.Lock()
	r.saved = len(addrs)
	r.mu.Unlock()
	return nil
}
