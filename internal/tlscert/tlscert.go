// Package tlscert embeds the public AionWG code-signing certificate.
// The private key (key.pem) is never embedded: the build uses it only to sign the EXE.
package tlscert

import _ "embed"

// Cert is public build metadata for optional Authenticode signing.
// Runtime startup never installs it into a Windows certificate store.
//
//go:embed cert.pem
var Cert []byte
