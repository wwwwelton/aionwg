package main

import (
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessConnection struct {
	Protocol string
	Local    string
	Remote   string
	State    string
}

type ManagedProcess struct {
	PID         uint32
	Name        string
	Path        string
	Policy      ProcessPolicy
	Connections []ProcessConnection
}

func effectiveProcessPolicy(rules []ProcessRule, name, path string) ProcessPolicy {
	name = strings.TrimSpace(name)
	path = cleanProcessPath(path)
	namePolicy := ProcessPolicy(PolicyDefault)
	for _, rule := range rules {
		policy := ProcessPolicy(strings.ToUpper(strings.TrimSpace(string(rule.Policy))))
		if !validProcessPolicy(policy) || policy == PolicyDefault {
			continue
		}
		if rule.Path != "" {
			if path != "" && strings.EqualFold(cleanProcessPath(rule.Path), path) {
				return policy
			}
			continue
		}
		if name != "" && strings.EqualFold(strings.TrimSpace(rule.Name), name) {
			namePolicy = policy
		}
	}
	return namePolicy
}

func cleanProcessPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func processMatches(p ManagedProcess, query string) bool {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(p.Name), query) || strings.Contains(strings.ToLower(p.Path), query) || strings.Contains(strconv.FormatUint(uint64(p.PID), 10), query) {
		return true
	}
	for _, c := range p.Connections {
		if strings.Contains(strings.ToLower(c.Protocol), query) || strings.Contains(strings.ToLower(c.Local), query) || strings.Contains(strings.ToLower(c.Remote), query) || strings.Contains(strings.ToLower(c.State), query) {
			return true
		}
	}
	return false
}

func filterManagedProcesses(processes []ManagedProcess, query string) []ManagedProcess {
	if strings.TrimSpace(query) == "" {
		return processes
	}
	out := make([]ManagedProcess, 0, len(processes))
	for _, process := range processes {
		if processMatches(process, query) {
			out = append(out, process)
		}
	}
	return out
}
