/* SPDX-License-Identifier: MIT */

package conn

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsUDPBufferSize = 4 << 20

var (
	qwave     = windows.NewLazySystemDLL("qwave.dll")
	qosCreate = qwave.NewProc("QOSCreateHandle")
	qosAdd    = qwave.NewProc("QOSAddSocketToFlow")
	qosSet    = qwave.NewProc("QOSSetFlow")
	qosClose  = qwave.NewProc("QOSCloseHandle")
)

func tuneWindowsSocket(sock windows.Handle) error {
	for _, option := range []int{windows.SO_RCVBUF, windows.SO_SNDBUF} {
		if err := windows.SetsockoptInt(sock, windows.SOL_SOCKET, option, windowsUDPBufferSize); err != nil {
			return fmt.Errorf("UDP buffer %d: %w", option, err)
		}
	}
	var disabled, returned uint32
	if err := windows.WSAIoctl(sock, windows.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&disabled)), 4, nil, 0, &returned, nil, 0); err != nil {
		return fmt.Errorf("SIO_UDP_CONNRESET: %w", err)
	}
	return nil
}

type socketQoS struct {
	handle windows.Handle
	flows  map[WinRingEndpoint]uint32
}

// The caller holds the socket's send lock; qWAVE setup happens only per destination.
func (q *socketQoS) mark(sock windows.Handle, endpoint *WinRingEndpoint) error {
	// qWAVE cannot classify loopback traffic; it never reaches a router.
	if endpoint.DstIP().IsLoopback() {
		return nil
	}
	if _, ok := q.flows[*endpoint]; ok {
		return nil
	}
	if q.handle == 0 {
		if err := qosCreate.Find(); err != nil {
			return err
		}
		version := [2]uint16{1, 0}
		if ok, _, err := qosCreate.Call(uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&q.handle))); ok == 0 {
			return fmt.Errorf("QOSCreateHandle: %w", err)
		}
		q.flows = make(map[WinRingEndpoint]uint32)
	}
	var flow uint32
	// Non-adaptive flow: do not probe bandwidth or shape the UDP tunnel.
	if ok, _, err := qosAdd.Call(uintptr(q.handle), uintptr(sock), uintptr(unsafe.Pointer(endpoint)), 4, 2, uintptr(unsafe.Pointer(&flow))); ok == 0 {
		return fmt.Errorf("QOSAddSocketToFlow: %w", err)
	}
	var dscp uint32 = 46
	if ok, _, err := qosSet.Call(uintptr(q.handle), uintptr(flow), 2, 4, uintptr(unsafe.Pointer(&dscp)), 0, 0); ok == 0 {
		q.close()
		return fmt.Errorf("QOSSetOutgoingDSCPValue: %w", err)
	}
	q.flows[*endpoint] = flow
	return nil
}

func (q *socketQoS) close() {
	if q.handle != 0 {
		qosClose.Call(uintptr(q.handle))
	}
	q.handle = 0
	q.flows = nil
}

// StdNetBind is the existing fallback when Windows registered I/O is unavailable.
func (q *socketQoS) markUDP(c *net.UDPConn, addr netip.AddrPort) error {
	var endpoint WinRingEndpoint
	if addr.Addr().Is4() {
		raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&endpoint))
		raw.Family = windows.AF_INET
		raw.Port = addr.Port()<<8 | addr.Port()>>8
		raw.Addr = addr.Addr().As4()
	} else {
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(&endpoint))
		raw.Family = windows.AF_INET6
		raw.Port = addr.Port()<<8 | addr.Port()>>8
		raw.Addr = addr.Addr().As16()
		if zone := addr.Addr().Zone(); zone != "" {
			index, err := strconv.ParseUint(zone, 10, 32)
			if err != nil {
				iface, err := net.InterfaceByName(zone)
				if err != nil {
					return err
				}
				index = uint64(iface.Index)
			}
			raw.Scope_id = uint32(index)
		}
	}
	// Avoid even RawConn.Control on the steady-state send path.
	if _, ok := q.flows[endpoint]; ok {
		return nil
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var markErr error
	if err := raw.Control(func(fd uintptr) { markErr = q.mark(windows.Handle(fd), &endpoint) }); err != nil {
		return err
	}
	return markErr
}
