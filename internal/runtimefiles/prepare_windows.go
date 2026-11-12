package runtimefiles

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Prepare uses Program Files, not a user-writable temp directory, for elevated DLL loads.
func Prepare(files []File) (string, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", fmt.Errorf("execute como Administrador para extrair as dependências embutidas")
	}
	root, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", err
	}
	base := filepath.Join(root, "AionWG-Runtime")
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(base)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("invalid runtime root: %s", base)
	}
	return extract(base, files)
}
