// Package tlscert embeds the public AionWG certificate into the executable.
// Releases reuse this certificate so users never need to reinstall it.
package tlscert

import _ "embed"

// Cert is the PEM certificate installed into the Windows trusted root store.
//
//go:embed cert.pem
var Cert []byte
