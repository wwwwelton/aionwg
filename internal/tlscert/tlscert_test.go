package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// The embedded certificate is trusted as a root on user machines, so it must only
// be able to vouch for signatures made with its own key.
func TestEmbeddedCertificateIsANonCACodeSigningLeaf(t *testing.T) {
	block, _ := pem.Decode(Cert)
	if block == nil {
		t.Fatal("cert.pem is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsCA || c.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("the certificate must not be a CA: trusting it would let its key holder mint trusted certificates")
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("key usage %v, want digital signature only", c.KeyUsage)
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatalf("extended key usage %v, want code signing only", c.ExtKeyUsage)
	}
	if c.NotAfter.Year() < 2100 {
		t.Fatalf("expires %v: it must not expire in practice", c.NotAfter)
	}
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		t.Fatalf("not self-signed: %v", err)
	}
	if c.Subject.CommonName != "AionWG Code Signing" {
		t.Fatalf("subject %q", c.Subject.CommonName)
	}
}
