//go:build windows && !external

package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"aionwg/internal/tlscert"
	"golang.org/x/sys/windows"
)

const certCN = "AionWG Code Signing"

// certPromptEnabled is false only in tests, which must never open a dialog.
var certPromptEnabled = true

// ensureCertTrusted asks the user whether to trust the embedded code-signing
// certificate when it is missing from the Root store. The program runs elevated, so
// "yes" installs it straight into the machine Root and TrustedPublisher stores; if
// that fails the standard certificate dialog opens so the user can finish it.
func ensureCertTrusted() error {
	block, _ := pem.Decode(tlscert.Cert)
	if block == nil {
		return errors.New("embedded certificate is not PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return err
	}
	sum := sha1.Sum(block.Bytes)
	thumb := hex.EncodeToString(sum[:])
	// Accept either store: machine or current user.
	if rootStoreHas("", thumb) || rootStoreHas("-user", thumb) {
		return nil
	}
	if !certPromptEnabled {
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
	p := filepath.Join(dir, "AionWG-Code-Signing.cer")
	if err := os.WriteFile(p, block.Bytes, 0o600); err != nil {
		return err
	}
	// The certificate is a non-CA code-signing leaf: trusting it only validates
	// signatures made with its own key, it cannot vouch for any other certificate.
	if exec.Command("certutil", "-f", "-addstore", "Root", p).Run() == nil {
		_ = exec.Command("certutil", "-f", "-addstore", "TrustedPublisher", p).Run()
		os.RemoveAll(dir)
		return nil
	}
	// Not elevated or certutil failed: the standard dialog, where the user picks the
	// store. It opens the file after this returns, so the file stays in %TEMP%.
	return exec.Command("rundll32.exe", "cryptext.dll,CryptExtOpenCER", p).Start()
}

// rootStoreHas reports whether the certutil Root store (machine when scope is empty,
// current user when "-user") contains the certificate with the given SHA-1 thumbprint.
func rootStoreHas(scope, thumb string) bool {
	args := []string{"-store", "Root"}
	if scope != "" {
		args = append([]string{scope}, args...)
	}
	out, err := exec.Command("certutil", args...).Output()
	return err == nil && strings.Contains(strings.ReplaceAll(strings.ToLower(string(out)), " ", ""), thumb)
}
