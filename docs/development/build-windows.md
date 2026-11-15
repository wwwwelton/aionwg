# Windows build

The canonical executable is `cmd/aionwg`. The root `main.go` remains a compatibility wrapper for existing `go build .` workflows.

## Cross-compile from Linux or WSL

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w' -o dist/AionWG.exe ./cmd/aionwg
```

For a packaged distribution with the embedded runtime assets available:

```bash
./build-aionwg-linux.sh --source "$PWD" --assets-dir "$PWD"
```

## Build on Windows

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\build-aionwg-windows.ps1 `
  -SourceDir "$PWD" -AssetsDir "$PWD"
```

Use `-NoPackage` for only the executable. Use `-UnverifiedModules` only as an explicit recovery option; it disables Go module checksum verification and is not a default.

## Embedded standalone build

`build-embedded.sh` and `build-embedded.ps1` rebuild the Shugo compatibility DLL when MinGW-w64 is available, embed WinDivert/Wintun/Shugo assets and create `dist/standalone/AionWG.exe`. Signing is separate and requires the private key outside Git.
