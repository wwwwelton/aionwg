# Security policy

AionWG handles VPN credentials, process metadata, native drivers and packet interception. Please do not disclose private keys, `.conf` files, PFX files, passwords or unredacted logs in public reports.

## Reporting

Use the repository owner's GitHub Security Advisories/private vulnerability reporting feature when it is enabled. If it is not enabled, the repository owner must configure a private reporting channel before accepting confidential reports. Do not guess or use an unverified email address.

If private reporting is unavailable, open a minimal public issue containing only a non-sensitive description and state that private contact is required. Do not attach exploit code or credentials.

## Include

- affected commit or release;
- Windows and Go versions;
- reproduction steps without secrets;
- impact and required privileges;
- whether WinDivert/Wintun or an embedded asset is involved;
- sanitized logs and checksums where useful.

## Scope

Examples include unsafe DLL loading, runtime extraction bypass, unauthorized WFP/driver changes, private-key disclosure, command injection in build/release scripts and packet-path memory safety issues.

A signed EXE is not proof of a signed kernel driver. Report driver-signing and trust-store concerns separately.
