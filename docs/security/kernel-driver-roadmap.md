# Native WFP kernel driver roadmap

## Current status

AionWG does **not** ship an `AionWFP.sys` callout driver. Native WFP currently means the user-mode policy engine backed by `fwpuclnt.dll`; packet capture and reinjection still use the selected WinDivert backend.

The following are therefore not implemented: WDK driver sources, INF installation, CAT package, IOCTL protocol, driver lifecycle service, kernel callout filters, kernel reinjection and a signed AionWG driver release.

## Required implementation stages

1. Define callout layers, flow context ownership, loop prevention and the user-mode/kernel-mode contract.
2. Implement the WDK callout and reinjection paths with bounded nonpaged allocations and unload-safe cleanup.
3. Add an authenticated IOCTL boundary. User-mode clients must not be able to install arbitrary filters or inject arbitrary packets.
4. Add INF installation, service lifecycle, rollback and recovery after partial installation.
5. Build a CAT package and use an approved Windows driver-signing workflow. An Authenticode-signed EXE does not satisfy kernel-driver signing requirements.
6. Validate on Windows 11 x64 with Driver Verifier, crash-dump collection, signed-package installation, upgrade, uninstall and rollback tests.

Until every stage is implemented and tested, the UI must report `Native WFP User Mode Policy + WinDivert` rather than a native WFP packet engine.
