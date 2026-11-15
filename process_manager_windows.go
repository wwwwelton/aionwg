//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const processQueryLimitedInformation = 0x1000

func processManagerSnapshot(rules []ProcessRule) []ManagedProcess {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	processes := make([]ManagedProcess, 0)
	byPID := make(map[uint32]int)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		name := windows.UTF16ToString(entry.ExeFile[:])
		path := processExecutablePath(entry.ProcessID)
		process := ManagedProcess{
			PID:    entry.ProcessID,
			Name:   name,
			Path:   path,
			Policy: effectiveProcessPolicy(rules, name, path),
		}
		byPID[process.PID] = len(processes)
		processes = append(processes, process)
	}
	if len(processes) == 0 {
		return processes
	}
	for pid, connections := range processConnections() {
		if index, ok := byPID[pid]; ok {
			processes[index].Connections = connections
		}
	}
	sort.Slice(processes, func(i, j int) bool {
		if strings.EqualFold(processes[i].Name, processes[j].Name) {
			return processes[i].PID < processes[j].PID
		}
		return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
	})
	return processes
}

func processExecutablePath(pid uint32) string {
	h, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func processConnections() map[uint32][]ProcessConnection {
	out := make(map[uint32][]ProcessConnection)

	parseProcessTable(getTable(procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPidAll), 24, out, func(row []byte) (uint32, ProcessConnection) {
		local := netip.AddrFrom4([4]byte{row[4], row[5], row[6], row[7]})
		remote := netip.AddrFrom4([4]byte{row[12], row[13], row[14], row[15]})
		return uint32(*(*uint32)(unsafe.Pointer(&row[20]))), ProcessConnection{
			Protocol: "TCP",
			Local:    netip.AddrPortFrom(local, ntohsDword(row[8:])).String(),
			Remote:   netip.AddrPortFrom(remote, ntohsDword(row[16:])).String(),
			State:    tcpState(row[0]),
		}
	})
	parseProcessTable(getTable(procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPidAll), 56, out, func(row []byte) (uint32, ProcessConnection) {
		local, okLocal := processIPv6(row[0:16])
		remote, okRemote := processIPv6(row[24:40])
		if !okLocal || !okRemote {
			return 0, ProcessConnection{}
		}
		return uint32(*(*uint32)(unsafe.Pointer(&row[52]))), ProcessConnection{
			Protocol: "TCP6",
			Local:    netip.AddrPortFrom(local, ntohsDword(row[20:])).String(),
			Remote:   netip.AddrPortFrom(remote, ntohsDword(row[44:])).String(),
			State:    tcpState(row[48]),
		}
	})
	parseProcessTable(getTable(procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPid), 12, out, func(row []byte) (uint32, ProcessConnection) {
		local := netip.AddrFrom4([4]byte{row[0], row[1], row[2], row[3]})
		return uint32(*(*uint32)(unsafe.Pointer(&row[8]))), ProcessConnection{
			Protocol: "UDP",
			Local:    netip.AddrPortFrom(local, ntohsDword(row[4:])).String(),
			Remote:   "*",
			State:    "OPEN",
		}
	})
	parseProcessTable(getTable(procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPid), 28, out, func(row []byte) (uint32, ProcessConnection) {
		local, ok := processIPv6(row[0:16])
		if !ok {
			return 0, ProcessConnection{}
		}
		return uint32(*(*uint32)(unsafe.Pointer(&row[24]))), ProcessConnection{
			Protocol: "UDP6",
			Local:    netip.AddrPortFrom(local, ntohsDword(row[20:])).String(),
			Remote:   "*",
			State:    "OPEN",
		}
	})
	return out
}

func parseProcessTable(table []byte, rowSize int, out map[uint32][]ProcessConnection, parse func([]byte) (uint32, ProcessConnection)) {
	if len(table) < 4 || rowSize <= 0 {
		return
	}
	count := int(binary.LittleEndian.Uint32(table))
	for i := 0; i < count; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > len(table) {
			return
		}
		pid, connection := parse(table[offset : offset+rowSize])
		if pid != 0 && connection.Protocol != "" {
			out[pid] = append(out[pid], connection)
		}
	}
}

func processIPv6(raw []byte) (netip.Addr, bool) {
	if len(raw) < 16 {
		return netip.Addr{}, false
	}
	var address [16]byte
	copy(address[:], raw[:16])
	return netip.AddrFrom16(address), true
}

func tcpState(state byte) string {
	states := [...]string{"", "CLOSED", "LISTEN", "SYN-SENT", "SYN-RECEIVED", "ESTABLISHED", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK", "DELETE-TCB"}
	if int(state) < len(states) {
		return states[state]
	}
	return fmt.Sprintf("STATE-%d", state)
}
