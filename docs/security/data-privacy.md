# Data privacy

AionWG stores imported profiles and settings under `%APPDATA%\\AionWG`. Profiles contain private keys and should be treated as secrets. Logs can contain process names, remote addresses, ports, endpoint history and diagnostic timing.

Before sharing diagnostics:

- remove `.conf` files and private keys;
- redact public IPs, endpoints, process paths and usernames where not needed;
- do not upload `internal/tlscert/key.pem`, PFX files or passwords;
- inspect `aionwg.log` and rotated logs.

The repository `.gitignore` excludes `.conf`, `.key`, `.pem` private-key material, archives and binaries. The public certificate is intentionally tracked; it is not a private credential.
