package runtimefiles

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type File struct {
	Name string
	Data []byte
}

func extract(base string, files []File) (string, error) {
	hash := sha256.New()
	for _, file := range files {
		if file.Name == "" || file.Name == "." || file.Name == ".." || strings.ContainsAny(file.Name, "\\/:") {
			return "", fmt.Errorf("invalid embedded filename %q", file.Name)
		}
		fmt.Fprintf(hash, "%s:%d:", file.Name, len(file.Data))
		hash.Write(file.Data)
	}
	dir := filepath.Join(base, fmt.Sprintf("%x", hash.Sum(nil)))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("invalid runtime directory: %s", dir)
	}
	for _, file := range files {
		path := filepath.Join(dir, file.Name)
		if _, err := os.Lstat(path); err == nil {
			if err := verify(path, file.Data); err != nil {
				return "", err
			}
			continue
		} else if !os.IsNotExist(err) {
			return "", err
		}
		tmp, err := os.CreateTemp(dir, ".extract-")
		if err != nil {
			return "", err
		}
		name := tmp.Name()
		_, writeErr := tmp.Write(file.Data)
		closeErr := tmp.Close()
		if writeErr != nil || closeErr != nil {
			os.Remove(name)
			if writeErr != nil {
				return "", writeErr
			}
			return "", closeErr
		}
		renameErr := os.Rename(name, path)
		os.Remove(name)
		// Another instance may have atomically installed the same payload first.
		if err := verify(path, file.Data); err != nil {
			if renameErr != nil {
				return "", renameErr
			}
			return "", err
		}
	}
	return dir, nil
}

func verify(path string, expected []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("runtime dependency is not a regular file: %s", path)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("runtime dependency differs from embedded bytes: %s", path)
	}
	return nil
}
