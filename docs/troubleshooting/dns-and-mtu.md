# DNS and MTU

DNS behavior depends on the selected mode and profile DNS values. In full-tunnel mode, tunnel DNS can be used when configured; `[n]` keeps Windows DNS direct according to the existing setting. Selective mode does not automatically make every Windows resolver query use the tunnel.

MTU is read from the profile and defaults only when the profile omits it. Do not change `config.go` globally to 1280. A WARP profile may legitimately specify 1280, but other WireGuard peers may require another value.

Use the self-test and packet-size diagnostics on the real link. A lower MTU can avoid fragmentation but is not a universal latency optimization.
