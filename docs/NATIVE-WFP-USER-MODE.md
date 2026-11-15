# Native WFP User Mode

AionWG now has a **Native WFP User Mode Policy Engine** backed directly by `fwpuclnt.dll`. It manages policy objects only; it is not a packet capture or packet reinjection engine.

## Implemented

- Dynamic BFE session through `FwpmEngineOpen0` and `FwpmEngineClose0`.
- AionWG-owned provider and sublayer with stable GUIDs.
- Transactional provider, sublayer, and filter changes.
- Application identity through `FwpmGetAppIdFromFileName0`.
- `BLOCK` filters at ALE connect and receive/accept layers for IPv4 and IPv6.
- Filter lookup, enumeration, deletion, and memory release through the corresponding `Fwpm*` APIs.
- Stable filter keys derived from the normalized executable path and WFP layer.
- Runtime status exposed separately from the packet backend.
- Asynchronous policy replacement after startup so TUI updates do not wait on BFE operations.

The dynamic session removes runtime objects when the process exits unexpectedly. Normal shutdown also explicitly deletes the AionWG objects before closing the session.
ALE authorization filters apply to new authorization decisions; they do not retroactively terminate an already authorized flow. Existing connections therefore require the same lifecycle behavior as Windows Firewall and must be handled by the packet backend or by an explicit reconnect.

## Policy semantics

- `BLOCK`: enforced by Native WFP ALE filters. A full executable path is required; a basename is resolved only when exactly one matching running process can provide that path.
- `TUNNEL`: remains selected and forwarded by the existing WinDivert packet engine and WireGuard/Wintun path.
- `BYPASS`: remains excluded by the existing packet classification path. A WFP `PERMIT` filter is not used as a fake route redirect.
- `DEFAULT`: follows the existing process policy behavior.

Native WFP therefore does not claim to replace WinDivert packet capture. The current architecture is **Native WFP User Mode Policy + WinDivert NETWORK Packet Backend**.

## Validation

The ABI tests verify the Windows SDK structure sizes and `FWPM_FILTER0.filterId` offset used by the Go wrappers. Portable tests, Windows cross-compilation, and Windows cross-platform `go vet` pass in the repository validation environment.

A live BFE session, elevated filter installation, Defender Firewall interaction, and real Windows traffic were not executed in this Linux environment. Those require Windows 11 runtime validation with appropriate privileges.

## Not included in this component

- WFP kernel-mode callout driver.
- `AionWFP.sys`, WDK project, INF, CAT, signing, or IOCTL transport.
- Native WFP packet capture/reinjection.
- WFP net-event subscription.
- A privileged service split for unprivileged TUI operation.

The future kernel packet backend remains a separate implementation stage. Until it exists and is validated, WinDivert remains the packet backend.
