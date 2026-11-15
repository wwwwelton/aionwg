package app

import "testing"

func TestEffectiveProcessPolicyPrefersExactPath(t *testing.T) {
	rules := []ProcessRule{
		{Name: "game.exe", Policy: PolicyBypass},
		{Name: "game.exe", Path: `C:\Games\game.exe`, Policy: PolicyTunnel},
	}
	if got := effectiveProcessPolicy(rules, "game.exe", `c:\games\GAME.EXE`); got != PolicyTunnel {
		t.Fatalf("path rule = %q, want %q", got, PolicyTunnel)
	}
	if got := effectiveProcessPolicy(rules, "game.exe", `C:\Other\game.exe`); got != PolicyBypass {
		t.Fatalf("name rule = %q, want %q", got, PolicyBypass)
	}
}

func TestFilterManagedProcessesMatchesPIDPathAndConnection(t *testing.T) {
	processes := []ManagedProcess{
		{PID: 42, Name: "game.exe", Path: `C:\Games\game.exe`, Connections: []ProcessConnection{{Protocol: "UDP", Remote: "203.0.113.10:9000"}}},
		{PID: 7, Name: "helper.exe", Path: `C:\Tools\helper.exe`},
	}
	for _, query := range []string{"42", "tools", "203.0.113.10", "udp"} {
		if got := filterManagedProcesses(processes, query); len(got) != 1 {
			t.Fatalf("query %q matched %d processes, want one", query, len(got))
		}
	}
}
