# Tunnel profiles

Profiles are `.conf` files stored under `%APPDATA%\\AionWG\\configs`. Import validates the file and refuses to overwrite a profile with the same name. Removal requires the existing TUI confirmation flow.

The parser preserves private keys, peer keys, endpoints, AllowedIPs, DNS, MTU and keepalive values. Private keys are not displayed in the dashboard or written to normal logs. The official export creates separate derived files and does not rewrite the imported source profile.

A live endpoint switch is an operational change, not a profile edit. Use `[v]` only with a configured or learned candidate and confirm the resulting handshake/route status.
