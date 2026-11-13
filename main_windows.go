//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// relaunchElevated restarts the program with a UAC prompt (WinDivert needs admin).
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	dir, _ := syscall.UTF16PtrFromString(cwd)
	args, _ := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	return windows.ShellExecute(0, verb, file, args, dir, windows.SW_NORMAL)
}

func main() {
	if !windows.GetCurrentProcessToken().IsElevated() {
		if err := relaunchElevated(); err != nil {
			fmt.Println("É preciso executar como Administrador:", err)
			fmt.Scanln()
			os.Exit(1)
		}
		return
	}
	if err := tuneRuntime(); err != nil {
		fmt.Fprintln(os.Stderr, "erro configurando runtime:", err)
		os.Exit(1)
	}
	if err := prepareRuntime(); err != nil {
		fmt.Println("erro preparando dependências:", err)
		os.Exit(1)
	}
	if err := runTUI(); err != nil {
		fmt.Println("erro:", err)
		fmt.Scanln()
		os.Exit(1)
	}
}
