//go:build windows && embedded

package main

import (
	"crypto/tls"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"aionwg/internal/tlscert"
	"golang.org/x/sys/windows"
)

const certCN = "DigiCert"

// ensureCertTrusted installs the embedded certificate into the machine root store
// when missing, after asking the user. Installing into Root requires administrator rights.
func ensureCertTrusted() error {
	if _, err := tls.X509KeyPair(tlscert.Cert, tlscert.Key); err != nil {
		return err
	}
	if exec.Command("certutil", "-store", "Root", certCN).Run() == nil {
		return nil
	}
	msg, _ := windows.UTF16PtrFromString("O certificado '" + certCN + "' do AionWG não está instalado como raiz confiável. Instalar agora?")
	title, _ := windows.UTF16PtrFromString("AionWG")
	const mbYesNo, mbIconQuestion, idYes = 0x4 | 0x20, 0, 6
	if r, _, _ := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0,
		uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), mbYesNo|mbIconQuestion); r != idYes {
		return nil
	}
	dir, err := os.MkdirTemp("", "aionwg-cert")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(p, tlscert.Cert, 0o600); err != nil {
		return err
	}
	return exec.Command("certutil", "-addstore", "-f", "Root", p).Run()
}
