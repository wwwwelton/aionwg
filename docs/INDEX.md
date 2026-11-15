# AionWG documentation

AionWG is a Windows x64 Go TUI for selective WireGuard routing through WinDivert, with optional native user-mode WFP policy management.

## Start here

- [Project overview](../README.md)
- [Quick start](user-guide/quick-start.md)
- [Windows build](development/build-windows.md)
- [Settings](configuration/settings.md)
- [Troubleshooting](troubleshooting/diagnostics.md)

## Architecture

- [Overview and migration map](architecture/overview.md)
- [Packet flow](architecture/packet-flow.md)
- [Process policy](architecture/process-policy.md)
- [WFP and WinDivert](architecture/wfp-and-windivert.md)
- [WireGuard](architecture/wireguard.md)
- [Routing](architecture/routing.md)
- [Runtime lifecycle](architecture/runtime-lifecycle.md)

## Development and releases

- [Getting started](development/getting-started.md)
- [Windows and cross-compilation](development/cross-compilation.md)
- [Testing](development/testing.md)
- [Release process](development/release-process.md)

## User and configuration guides

- [TUI](user-guide/tui.md)
- [Process manager](user-guide/process-manager.md)
- [Tunnel manager](user-guide/tunnel-manager.md)
- [Route optimizer](user-guide/route-optimizer.md)
- [WireGuard profiles](configuration/wireguard-profiles.md)
- [Process rules](configuration/process-rules.md)

## Operations and security

- [Connection issues](troubleshooting/connection-issues.md)
- [DNS and MTU](troubleshooting/dns-and-mtu.md)
- [Drivers and elevation](troubleshooting/drivers.md)
- [Diagnostics](troubleshooting/diagnostics.md)
- [Threat model](security/threat-model.md)
- [Privileges and drivers](security/privileges-and-drivers.md)
- [Code signing](security/code-signing.md)
- [Data privacy](security/data-privacy.md)
- [Licensing assessment](security/licensing.md)

## Architectural decisions

- [Root package migration](adr/0001-root-package-migration.md)
- [Native WFP policy engine](adr/0002-native-wfp-policy.md)

Historical audit material remains in [AIONWG-2-AUDIT.md](AIONWG-2-AUDIT.md). It records earlier observations; current implementation status is updated in the documents above.
