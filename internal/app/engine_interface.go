//go:build windows

package app

import "net/netip"

// TunnelEngine abstracts both WireGuard and Pingless engines.
type TunnelEngine interface {
	Stats() Stats
	SetProcesses(names []string)
	SetProcessRules(rules []ProcessRule, names []string)
	SetMirror(on bool)
	SetUDPDuplicate(on bool)
	SetUDPRatio(originals, copies int)
	SetUDPForce(on bool)
	SetUDPNewestOut(on bool)
	SetUDPNewestIn(on bool)
	SetFullTunnel(on bool)
	SetNoDNS(off bool)
	SetWFP(on bool)
	SetWFPApps(names []string)
	SetEndpoint(ep netip.AddrPort) error
	SetEndpointString(v string) error
	WGConf() *WGConf
	EndpointRows() []endpointRow
	EndpointCandidates(existingRows []endpointRow) []netip.AddrPort
	ObservedRemotes() []netip.Addr
	EndpointAddrs() []netip.Addr
	Close()
}
