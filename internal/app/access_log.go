package app

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// accessMaxPerProg caps the remotes listed per program in one tick so a
// scanning app cannot make the log line unbounded.
const accessMaxPerProg = 50

// accessLog collects which remote endpoints each program sent outbound packets
// to, between two reports.
type accessLog struct {
	mu   sync.Mutex
	seen map[string]map[netip.AddrPort]struct{} // program name -> remotes
}

// add records that program name sent a packet to remote.
func (a *accessLog) add(name string, remote netip.AddrPort) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen == nil {
		a.seen = map[string]map[netip.AddrPort]struct{}{}
	}
	set := a.seen[name]
	if set == nil {
		set = map[netip.AddrPort]struct{}{}
		a.seen[name] = set
	}
	if len(set) < accessMaxPerProg {
		set[remote] = struct{}{}
	}
}

// take returns the lines for one report and clears the collected state. Lines
// are sorted by program name; each lists its remotes in address order.
func (a *accessLog) take() []string {
	a.mu.Lock()
	seen := a.seen
	a.seen = nil
	a.mu.Unlock()
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names))
	for _, n := range names {
		rs := make([]string, 0, len(seen[n]))
		for r := range seen[n] {
			rs = append(rs, r.String())
		}
		sort.Strings(rs)
		lines = append(lines, n+" -> "+strings.Join(rs, ", "))
	}
	return lines
}
