//go:build windows

package main

// Minimal WinDivert 2.x bindings (loads WinDivert.dll at runtime, no cgo).

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	divertLayerNetwork = 0
	divertLayerSocket  = 3

	divertFlagSniff    = 0x0001
	divertFlagRecvOnly = 0x0004

	divertShutdownBoth = 3
)

// divertAddress mirrors WINDIVERT_ADDRESS (80 bytes).
type divertAddress struct {
	Timestamp int64
	bits      uint32 // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 ...
	reserved2 uint32
	IfIdx     uint32 // Network.IfIdx
	SubIfIdx  uint32 // Network.SubIfIdx
	_         [56]byte
}

func (a *divertAddress) Outbound() bool { return a.bits&(1<<17) != 0 }
func (a *divertAddress) Impostor() bool { return a.bits&(1<<19) != 0 }

func (a *divertAddress) SetOutbound(v bool) {
	if v {
		a.bits |= 1 << 17
	} else {
		a.bits &^= 1 << 17
	}
}

func (a *divertAddress) SetIPv6(v bool) {
	if v {
		a.bits |= 1 << 20
	} else {
		a.bits &^= 1 << 20
	}
}

var (
	divertDLL    = windows.NewLazyDLL("WinDivert.dll")
	procOpen     = divertDLL.NewProc("WinDivertOpen")
	procRecv     = divertDLL.NewProc("WinDivertRecv")
	procSend     = divertDLL.NewProc("WinDivertSend")
	procShutdown = divertDLL.NewProc("WinDivertShutdown")
	procClose    = divertDLL.NewProc("WinDivertClose")
	procSetParam = divertDLL.NewProc("WinDivertSetParam")
	procCompile  = divertDLL.NewProc("WinDivertHelperCompileFilter")
)

type divertHandle uintptr

func divertLoad() error {
	if err := divertDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll não encontrado (coloque WinDivert.dll e WinDivert64.sys ao lado do .exe): %w", err)
	}
	return nil
}

// divertCheckFilter asks WinDivert to compile the filter and returns its exact error.
func divertCheckFilter(filter string, layer int) error {
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return err
	}
	var errStr *byte
	var errPos uint32
	r, _, _ := procCompile.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), 0, 0,
		uintptr(unsafe.Pointer(&errStr)), uintptr(unsafe.Pointer(&errPos)))
	if r != 0 {
		return nil
	}
	msg := "erro desconhecido"
	if errStr != nil {
		msg = windows.BytePtrToString(errStr)
	}
	return fmt.Errorf("filtro WinDivert inválido: %s (posição %d em %q)", msg, errPos, filter)
}

func divertOpen(filter string, layer int, priority int16, flags uint64) (divertHandle, error) {
	if err := divertLoad(); err != nil {
		return 0, err
	}
	if err := divertCheckFilter(filter, layer); err != nil {
		return 0, err
	}
	f, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r, _, e := procOpen.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), uintptr(priority), uintptr(flags))
	if windows.Handle(r) == windows.InvalidHandle {
		switch e {
		case windows.ERROR_ACCESS_DENIED:
			return 0, errors.New("WinDivert: acesso negado (execute como Administrador)")
		case windows.ERROR_INVALID_PARAMETER:
			return 0, fmt.Errorf("WinDivert: parâmetro inválido (filtro %q)", filter)
		case windows.Errno(577): // ERROR_INVALID_IMAGE_HASH
			return 0, errors.New("WinDivert: driver sem assinatura válida / bloqueado (Secure Boot, anti-cheat ou antivírus?)")
		}
		return 0, fmt.Errorf("WinDivertOpen: %w", e)
	}
	return divertHandle(r), nil
}

func (h divertHandle) setParam(param int, value uint64) {
	procSetParam.Call(uintptr(h), uintptr(param), uintptr(value))
}

func (h divertHandle) recv(buf []byte, addr *divertAddress) (int, error) {
	var n uint32
	r, _, e := procRecv.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return 0, e
	}
	return int(n), nil
}

// recvEvent receives one event from a layer that carries no packet data
// (FLOW, SOCKET). The WinDivert documentation requires pPacket == NULL and
// packetLen == 0 for those layers.
func (h divertHandle) recvEvent(addr *divertAddress) error {
	r, _, e := procRecv.Call(uintptr(h), 0, 0, 0, uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

func (h divertHandle) send(pkt []byte, addr *divertAddress) error {
	var n uint32
	r, _, e := procSend.Call(uintptr(h), uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

func (h divertHandle) shutdown() { procShutdown.Call(uintptr(h), divertShutdownBoth) }
func (h divertHandle) close()    { procClose.Call(uintptr(h)) }
