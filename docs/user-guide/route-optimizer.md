# Route optimizer

AionWG can compare configured or discovered WireGuard endpoint addresses and
switch only after a candidate completes a handshake. The current implementation
uses direct ICMP measurements for endpoint ranking and validates a switch against
the real game-ping measurement before keeping it.

Current safeguards:

- The current endpoint is retained unless an alternative beats it by the
  configured margin.
- Endpoint trials are limited; failed handshakes are remembered temporarily.
- A route switch is spaced by a cooldown and is not an endpoint scan burst.
- Candidates come from configured endpoint resolution and previously proven
  addresses, not arbitrary Cloudflare internal routes.
- Route history is stored per profile under the application data directory.

The route screen and the `b`/`v` controls expose the current route and endpoint
selection. ICMP RTT is not the same measurement as game RTT; use the diagnostics
and the application target configured by `t` before judging a change.

Configured relays can be entered from the command palette (`Ctrl+K` →
`Configurar relays`) as `host:port` values. AionWG resolves and probes them
with direct ICMP in a background loop, then shows RTT/P50/P95/jitter/loss on
the route screen. This is a measured relay candidate, not proof that traffic
is currently routed through it; use a validated WireGuard profile to switch
the actual packet path.

AionWG does not claim to control Cloudflare's internal relay selection and does
not guarantee lower latency. WARP/WARP+ multipath remains an optional AionWG
feature and is documented separately from Cloudflare's supported client modes.
