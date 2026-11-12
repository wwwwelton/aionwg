// Package tlscert embeds the AionWG self-signed certificate and its private key.
// The files are regenerated on every embedded build by `go run ./internal/tlscert/gen`.
package tlscert

import _ "embed"

// Cert is the PEM certificate that gets installed into the Windows trusted root store.
//
//go:embed cert.pem
var Cert []byte

// Key is the PEM private key for Cert. It ships inside the binary by design.
//
//go:embed key.pem
var Key []byte
