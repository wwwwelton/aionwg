// Package tlscert embeds the public AionWG code-signing certificate into the
// executable. The private key (key.pem) is never embedded: the build uses it
// only to sign the EXE.
package tlscert

import _ "embed"

// Cert is the PEM certificate installed into the Windows trusted root store.
//
//go:embed cert.pem
var Cert []byte
