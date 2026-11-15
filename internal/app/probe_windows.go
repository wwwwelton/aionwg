//go:build windows

package app

import "bytes"

// probeConfFn picks the identity used to handshake-test candidate endpoints;
// tests replace it.
var probeConfFn = otherProfileConf

// otherProfileConf returns another saved profile that talks to the same server
// key (same WARP network) but has its own private key. A handshake with the live
// key from a second socket makes the server drop or redirect the live session
// (observed: ~20 s of 85% loss), so a test is only isolated when it uses a
// different identity. It returns nil when no such profile exists.
func otherProfileConf(live *WGConf, profile string) *WGConf {
	if len(live.Peers) == 0 {
		return nil
	}
	for _, name := range listConfigs() {
		if name == profile {
			continue
		}
		c, err := readConfig(name)
		if err != nil || len(c.Peers) == 0 {
			continue
		}
		if bytes.Equal(c.PrivateKey, live.PrivateKey) || !bytes.Equal(c.Peers[0].PublicKey, live.Peers[0].PublicKey) {
			continue
		}
		return c
	}
	return nil
}
