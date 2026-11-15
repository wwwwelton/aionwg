# Cross-compilation

AionWG is built with `CGO_ENABLED=0` for Windows amd64. The root package is the entrypoint because the current code still shares concrete engine and TUI types in one package.

The build scripts preserve these compatibility entrypoints:

- `build-aionwg-linux.sh`: Linux/WSL to Windows x64, optional ZIP.
- `build-aionwg-windows.ps1`: native Windows build, optional WSL refresh and ZIP.
- `build-embedded.sh` / `build-embedded.ps1`: standalone embedded-runtime build.
- `build.sh`: legacy minimal cross-build.
- `Instalar-Go-Compilar-AionWG.ps1`: legacy installation and build helper.

The scripts do not copy `.conf`, `.key`, `.pem` or `.env` files into packages. Native assets are selected from the source/assets directory or an explicit ZIP; no downloads are performed by the build.
