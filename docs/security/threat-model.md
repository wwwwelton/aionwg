# Threat model

AionWG handles private WireGuard material, native Windows drivers/DLLs, process metadata and remote network destinations.

## Protected assets

- WireGuard private and preshared keys.
- Embedded/runtime native binaries.
- User settings and imported profiles.
- Integrity of packet capture and reinjection.
- Windows firewall/BFE state.

## Main threats

- A modified DLL or driver loaded from a writable search path.
- Accidental disclosure of profiles or logs.
- An incorrect process identity causing traffic to be blocked or tunneled.
- A stale WFP filter surviving a failed shutdown.
- Malicious or compromised release-signing credentials.
- Anti-cheat or security software treating capture as hostile.

## Mitigations

Runtime files are content-addressed and verified before use. DLL search paths are restricted in embedded mode. Config files and logs use restricted creation modes where supported. Native WFP objects use an AionWG provider/sublayer and a dynamic session. Release signing secrets stay outside Git.

The threat model does not treat a self-signed code-signing certificate as a platform trust root. The application must not silently install it.
