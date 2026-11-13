//go:build windows && embedded

package main

import (
	"crypto/sha1"
	"crypto/tls"
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

const certCN = "DigiCert"

// ensureCertTrusted asks the user whether to install the embedded certificate when it
// is missing from the Root store, then opens the Windows certificate dialog so the
// user picks the store (the wizard asks for elevation when needed).
func ensureCertTrusted() error {
	if _, err := tls.X509KeyPair(tlscert.Cert, tlscert.Key); err != nil {
		return err
	}
	block, _ := pem.Decode(tlscert.Cert)
	if block == nil {
		return errors.New("embedded certificate is not PEM")
	}
	sum := sha1.Sum(block.Bytes)
	thumb := hex.EncodeToString(sum[:])
	// Match by thumbprint: every build has a new key, so CN alone is not enough.
	// Accept either store: the wizard may install into the current user's Root.
	if rootStoreHas("", thumb) || rootStoreHas("-user", thumb) {
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
	// Opened by the dialog after this returns, so the file is left in %TEMP%.
	p := filepath.Join(dir, certCN+".cer")
	if err := os.WriteFile(p, block.Bytes, 0o600); err != nil {
		return err
	}
	// cryptext.dll shows the standard certificate dialog with "Instalar Certificado".
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
