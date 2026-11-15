# Build entry points

The root scripts remain compatibility entry points. These wrappers provide stable
paths for new tooling without changing their behavior:

| Purpose | Wrapper | Legacy script |
| --- | --- | --- |
| Linux to Windows x64 | `scripts/build-windows-cross.sh` | `build-aionwg-linux.sh` |
| Windows x64 build | `scripts/build-windows.ps1` | `build-aionwg-windows.ps1` |
| Embedded standalone build on Linux/WSL | `scripts/build-embedded.sh` | `build-embedded.sh` |
| Embedded standalone build on Windows | `scripts/build-embedded.ps1` | `build-embedded.ps1` |

The wrappers forward all arguments. They do not install drivers, change firewall
state or move private configuration files.
