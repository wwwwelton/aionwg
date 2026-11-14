// Command gen creates the AionWG code-signing certificate and key in
// internal/tlscert. cert.pem (public) is tracked and embedded in the EXE so the
// program can offer to trust it; key.pem is the private key, kept out of git and
// out of the EXE, and used only by the build to sign the EXE (Authenticode).
// The certificate has no practical expiry (notAfter 9999-12-31, RFC 5280's "no
// well-defined expiration") and is meant to sign every build: keep key.pem safe,
// because rotating it makes every machine trust a new certificate.
// The pair is reused when cert.pem is valid; pass -new to rotate it.
// Run by build-embedded.sh and build-embedded.ps1 before every build.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	rotate := flag.Bool("new", false, "replace the existing certificate and key")
	flag.Parse()
	dir := filepath.Join("internal", "tlscert")
	if _, err := os.Stat(dir); err != nil {
		log.Fatalf("run from the repository root: %v", err)
	}
	if !*rotate {
		if c, err := os.ReadFile(filepath.Join(dir, "cert.pem")); err == nil {
			if block, _ := pem.Decode(c); block != nil {
				if _, err := x509.ParseCertificate(block.Bytes); err == nil {
					log.Print("reusing existing certificate (use -new to rotate)")
					return
				}
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "AionWG Code Signing", Organization: []string{"AionWG"}},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false, // a trusted leaf, not a CA: no certificate can chain to it
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		log.Fatal(err)
	}
	log.Print("new certificate created; BACK UP internal/tlscert/key.pem (it is not in git)")
}
