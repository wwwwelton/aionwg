//go:build !windows

package conn

import (
	"net"
	"net/netip"
)

// Socket QoS is Windows-specific; other platforms retain their existing controls.
type socketQoS struct{}

func (*socketQoS) close()                                     {}
func (*socketQoS) markUDP(*net.UDPConn, netip.AddrPort) error { return nil }
