# WireGuard profiles

AionWG accepts wg-quick-style profiles with `[Interface]` and one or more `[Peer]` sections. Required values are a private key, at least one address, a peer public key and a valid `host:port` endpoint.

Supported interface values include `PrivateKey`, `Address`, `DNS`, `MTU` and `ListenPort`. Supported peer values include `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs` and `PersistentKeepalive`.

The attached Cloudflare WARP profile is an input profile, not a repository asset. Do not commit it or its private key. Its MTU is profile-specific; AionWG does not globally force MTU 1280.
