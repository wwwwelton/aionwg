# Security policy

AionWG handles VPN credentials, process metadata, native drivers and packet interception. Please do not disclose private keys, `.conf` files, PFX files, passwords or unredacted logs in public reports.

## Reporting

The official channel is GitHub's private vulnerability reporting feature:
open this repository's **Security** tab, choose **Advisories**, then **Report
a vulnerability**. This channel must be enabled by the repository owner; no
security email address is configured in this repository.

If private reporting is unavailable, open a minimal public issue containing
only a non-sensitive description and state that private contact is required.
Do not attach exploit code, credentials, private keys or unredacted logs.

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
