// Command gen creates the self-signed AionWG certificate and key in internal/tlscert.
// The pair is reused when present and valid, so builds keep the same certificate.
// Pass -new to rotate it (machines that trusted the old one must trust the new one).
// Run by build-embedded.sh and build-embedded.ps1 before every embedded build.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
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
		_, errC := os.Stat(filepath.Join(dir, "cert.pem"))
		_, errK := os.Stat(filepath.Join(dir, "key.pem"))
		if errC == nil && errK == nil {
			if c, err1 := os.ReadFile(filepath.Join(dir, "cert.pem")); err1 == nil {
				if k, err2 := os.ReadFile(filepath.Join(dir, "key.pem")); err2 == nil {
					if _, err := tls.X509KeyPair(c, k); err == nil {
						log.Print("reusing existing certificate (use -new to rotate)")
						return
					}
				}
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "DigiCert"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
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
}
