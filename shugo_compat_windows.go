//go:build windows

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var shugoKernel = windows.NewLazySystemDLL("kernel32.dll")
var shugoAlloc = shugoKernel.NewProc("VirtualAllocEx")
var shugoFree = shugoKernel.NewProc("VirtualFreeEx")
var shugoCreateThread = shugoKernel.NewProc("CreateRemoteThread")
var shugoThreadResult = shugoKernel.NewProc("GetExitCodeThread")

type shugoTarget struct {
	pid          uint32
	process      windows.Handle
	base         uintptr
	stop, status uintptr
	reported     bool
}

func shugoModules(pid uint32, match func(windows.ModuleEntry32) bool) (windows.ModuleEntry32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return windows.ModuleEntry32{}, err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Module32First(snapshot, &entry); err == nil; err = windows.Module32Next(snapshot, &entry) {
		if match(entry) {
			return entry, nil
		}
	}
	return windows.ModuleEntry32{}, windows.ERROR_MOD_NOT_FOUND
}

func shugoNamedModule(pid uint32, name string) (windows.ModuleEntry32, error) {
	return shugoModules(pid, func(m windows.ModuleEntry32) bool { return strings.EqualFold(windows.UTF16ToString(m.Module[:]), name) })
}

// shugoRemoteCall runs function(argument) in the target. started reports that
// the remote thread exists: after that, an error (timeout) means it may still
// be running, so the caller must not assume the call had no effect.
func shugoRemoteCall(process windows.Handle, function, argument uintptr) (code uint32, started bool, err error) {
	h, _, err := shugoCreateThread.Call(uintptr(process), 0, 0, function, argument, 0, 0)
	if h == 0 {
		return 0, false, err
	}
	defer windows.CloseHandle(windows.Handle(h))
	result, err := windows.WaitForSingleObject(windows.Handle(h), 5000)
	if err != nil {
		return 0, true, err
	}
	if result != windows.WAIT_OBJECT_0 {
		return 0, true, fmt.Errorf("remote thread wait: %d (thread may still be running)", result)
	}
	ok, _, err := shugoThreadResult.Call(h, uintptr(unsafe.Pointer(&code)))
	if ok == 0 {
		return 0, true, err
	}
	return code, true, nil
}

func shugoLoadRemote(process windows.Handle, pid uint32, path string) error {
	address := shugoKernel.NewProc("LoadLibraryW").Addr()
	owner, err := shugoModules(windows.GetCurrentProcessId(), func(m windows.ModuleEntry32) bool {
		return address >= m.ModBaseAddr && address-m.ModBaseAddr < uintptr(m.ModBaseSize)
	})
	if err != nil {
		return err
	}
	remoteOwner, err := shugoNamedModule(pid, windows.UTF16ToString(owner.Module[:]))
	if err != nil {
		return err
	}
	path16, err := windows.UTF16FromString(path)
	if err != nil {
		return err
	}
	size := uintptr(len(path16) * 2)
	memory, _, err := shugoAlloc.Call(uintptr(process), 0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if memory == 0 {
		return err
	}
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&path16[0])), int(size))
	if err = windows.WriteProcessMemory(process, memory, &buffer[0], size, nil); err != nil {
		shugoFree.Call(uintptr(process), memory, 0, windows.MEM_RELEASE)
		return err
	}
	_, started, err := shugoRemoteCall(process, remoteOwner.ModBaseAddr+address-owner.ModBaseAddr, memory)
	// On timeout the remote loader can still be reading its argument; keep that
	// allocation alive. If the thread never started nothing can read it.
	if err == nil || !started {
		shugoFree.Call(uintptr(process), memory, 0, windows.MEM_RELEASE)
	}
	if err != nil {
		return err
	}
	_, err = shugoNamedModule(pid, filepath.Base(path))
	return err
}

func shugoProcessIDs() ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var pids []uint32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), "shugogg-companion.exe") {
			pids = append(pids, entry.ProcessID)
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return pids, nil
}

func openShugoTarget(pid uint32) (*shugoTarget, error) {
	access := uint32(windows.PROCESS_CREATE_THREAD | windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION | windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ | windows.SYNCHRONIZE)
	process, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return nil, err
	}
	var path [32768]uint16
	length := uint32(len(path))
	err = windows.QueryFullProcessImageName(process, 0, &path[0], &length)
	if err != nil || !strings.EqualFold(filepath.Base(windows.UTF16ToString(path[:length])), "shugogg-companion.exe") {
		windows.CloseHandle(process)
		return nil, fmt.Errorf("shugoTarget identity check failed: %v", err)
	}
	return &shugoTarget{pid: pid, process: process}, nil
}

func (t *shugoTarget) disable(logf func(string, ...any)) error {
	defer windows.CloseHandle(t.process)
	result, err := windows.WaitForSingleObject(t.process, 0)
	if err != nil {
		return err
	}
	if result == windows.WAIT_OBJECT_0 {
		return nil
	}
	code, _, err := shugoRemoteCall(t.process, t.base+t.stop, 0)
	if err != nil || code != 0 {
		return fmt.Errorf("Shugo PID %d: restore failed: code=%d error=%v", t.pid, code, err)
	}
	logf("Shugo PID %d: original capture API restored", t.pid)
	return nil
}

// shugoCompat keeps Shugo's TCP-table view in sync with the [m] mirror: the
// game connection is shown as the loopback relay copy only while it is on.
type shugoCompat struct {
	stop chan struct{}
	done chan struct{}
}

// startShugoCompat starts the supervisor; after (may be nil) is the previous
// supervisor's done channel: its restore must finish before this one hooks.
func startShugoCompat(logf func(string, ...any), after <-chan struct{}) *shugoCompat {
	c := &shugoCompat{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		if after != nil {
			select {
			case <-after:
			case <-c.stop:
				return
			}
		}
		if err := c.run(logf); err != nil {
			logf("Shugo: %v", err)
		}
	}()
	return c
}

func (c *shugoCompat) Close() {
	close(c.stop)
	<-c.done
}

func (c *shugoCompat) run(logf func(string, ...any)) (resultErr error) {
	path := compatPath
	dll, err := windows.LoadDLL(path)
	if err != nil {
		return fmt.Errorf("compatibilidade indisponível (%s): %w", path, err)
	}
	defer dll.Release()
	offsets := map[string]uintptr{}
	for _, name := range []string{"AionWGCompatStart", "AionWGCompatStop", "AionWGCompatStatus"} {
		proc, err := dll.FindProc(name)
		if err != nil {
			return err
		}
		offsets[name] = proc.Addr() - uintptr(dll.Handle)
	}
	active := map[uint32]*shugoTarget{}
	failed := map[uint32]bool{}
	defer func() {
		for _, t := range active {
			if err := t.disable(logf); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	snapshotFailed := false
	for {
		pids, err := shugoProcessIDs()
		if err != nil {
			if !snapshotFailed {
				logf("Shugo: lista de processos indisponível (%v); tentando de novo", err)
				snapshotFailed = true
			}
			select {
			case <-c.stop:
				return nil
			case <-ticker.C:
			}
			continue
		}
		snapshotFailed = false
		live := map[uint32]bool{}
		for _, pid := range pids {
			live[pid] = true
			if t := active[pid]; t != nil {
				if !t.reported {
					count, _, err := shugoRemoteCall(t.process, t.base+t.status, 0)
					if err != nil {
						logf("Shugo PID %d: status falhou (%v); desativando este alvo", pid, err)
						if derr := t.disable(logf); derr != nil {
							logf("Shugo PID %d: %v", pid, derr)
						}
						delete(active, pid)
						failed[pid] = true
						continue
					}
					if count > 0 {
						logf("Shugo PID %d: par de conexão do jogo/espelho apresentado (%d)", pid, count)
						t.reported = true
					}
				}
				continue
			}
			if failed[pid] {
				continue
			}
			t, err := openShugoTarget(pid)
			if err != nil {
				logf("Shugo PID %d: %v", pid, err)
				failed[pid] = true
				continue
			}
			module, err := shugoNamedModule(pid, "shugo-compat.dll")
			if err != nil {
				err = shugoLoadRemote(t.process, pid, path)
				if err == nil {
					module, err = shugoNamedModule(pid, "shugo-compat.dll")
				}
			}
			if err != nil {
				windows.CloseHandle(t.process)
				logf("Shugo PID %d: falha ao anexar: %v", pid, err)
				failed[pid] = true
				continue
			}
			if !strings.EqualFold(windows.UTF16ToString(module.ExePath[:]), path) {
				windows.CloseHandle(t.process)
				return fmt.Errorf("o Shugo tem outra DLL de compatibilidade carregada; reinicie o Shugo")
			}
			t.base, t.stop, t.status = module.ModBaseAddr, offsets["AionWGCompatStop"], offsets["AionWGCompatStatus"]
			code, started, err := shugoRemoteCall(t.process, t.base+offsets["AionWGCompatStart"], 0)
			if started && err != nil {
				// The loader may still finish Start: keep the target so exit/disable runs the idempotent Stop.
				logf("Shugo PID %d: ativação sem resposta (%v); será desfeita ao sair", pid, err)
				active[pid] = t
				continue
			}
			if err != nil || code != 0 {
				windows.CloseHandle(t.process)
				logf("Shugo PID %d: falha ao ativar: code=%d error=%v", pid, code, err)
				failed[pid] = true
				continue
			}
			active[pid] = t
			logf("Shugo PID %d: compatibilidade ativa (relay do espelho)", pid)
		}
		for pid, t := range active {
			if !live[pid] {
				windows.CloseHandle(t.process)
				delete(active, pid)
			}
		}
		for pid := range failed {
			if !live[pid] {
				delete(failed, pid)
			}
		}
		select {
		case <-c.stop:
			return nil
		case <-ticker.C:
		}
	}
}
