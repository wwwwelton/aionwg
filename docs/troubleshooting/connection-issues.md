# Connection issues

Check in this order:

1. The profile parses and the endpoint resolves.
2. The WireGuard handshake becomes recent.
3. The tunnel gateway responds to the selected probe.
4. The process rule is effective and the packet backend is active.
5. The game destination has been observed and is covered by the active route.
6. DNS, MTU and IPv4/IPv6 behavior match the profile.

Do not infer game latency from the VPN endpoint alone. Endpoint switching is conservative and should not interrupt an existing connection for a marginal result. If WARP multipath is enabled, disable `[h]` when independent sessions or different exits create instability.
