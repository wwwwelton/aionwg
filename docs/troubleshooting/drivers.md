# Drivers and elevation

WinDivert capture requires an elevated Windows process and a compatible `WinDivert.dll`/`WinDivert64.sys` pair. Wintun is used by the DPS meter path and is not the primary tunnel interface.

AionWG currently has no project-owned WFP kernel callout driver, INF, CAT or IOCTL service. Native WFP user mode uses the Windows BFE through `fwpuclnt.dll` for policy filters only.

If startup fails, verify asset integrity, architecture (Windows x64), elevation, antivirus/anti-cheat policy and whether another process owns the expected capture resources. Do not install an unverified driver from a random download.
