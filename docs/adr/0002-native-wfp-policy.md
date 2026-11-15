# ADR 0002: Native WFP is a policy backend

- Status: accepted
- Date: 2026-11-15

## Decision

Use `fwpuclnt.dll` from Go for provider, sublayer, transaction and ALE App ID policy management. Keep WinDivert NETWORK as the packet backend until a separately validated WFP callout driver exists.

## Rationale

WFP user-mode filters can authorize or block flows but cannot, by themselves, redirect arbitrary application packets into WireGuard/Wintun. Calling the policy layer a packet engine would be inaccurate and would hide the need for a WDK driver, installation, signing, reinjection and loop protection.

## Consequences

`BLOCK` can be native WFP. `TUNNEL` and `BYPASS` remain in the common WinDivert classifier. The dashboard reports policy and packet backends separately. Kernel-mode work remains an independent future project.
