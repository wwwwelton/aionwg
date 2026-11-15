# Diagnostics

Use `[x]` for the current self-test and `[g]` for the diagnostics panel. The dashboard distinguishes:

- driver/runtime preparation;
- capture/interception;
- virtual tunnel;
- WireGuard handshake;
- applied route;
- destination reachability;
- Native WFP policy session and filters.

The log at `%APPDATA%\\AionWG\\aionwg.log` is bounded and asynchronous. It can contain process names, remote IPs and ports. Remove those values before sharing a report publicly.

A successful interface or handshake is not proof that a selected application is using the intended route. Check the process policy, packet backend, endpoint and destination measurements separately.
