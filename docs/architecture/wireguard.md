# WireGuard integration

AionWG parses wg-quick-style profiles, resolves peer endpoints, configures the vendored WireGuard-go device through UAPI, and connects it to the split-TUN implementation.

The profile parser accepts `PrivateKey`, `Address`, `DNS`, `MTU`, `ListenPort`, peer keys, `Endpoint`, `AllowedIPs` and `PersistentKeepalive`. Private keys are held in memory only as required to configure the device; they are not rendered into the TUI or diagnostic logs.

`AllowedIPs` controls the destinations considered reachable through a peer. In selective mode, observed game/application destinations can be added to the active route state without rewriting the source profile. The official export path writes a separate profile with mode-specific routes.

The vendored module is pinned by `go.mod` to `./third_party/wireguard-go`. See `third_party/wireguard-go/VENDORED.txt` for the source commit and local removals.
