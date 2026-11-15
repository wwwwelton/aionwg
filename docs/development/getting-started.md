# Development getting started

## Prerequisites

- Go version from `go.mod` (`go 1.24.2`, local toolchain `1.24.7`).
- Git.
- Windows 11 x64 for runtime, WinDivert, Wintun and elevated tests.
- MinGW-w64 and `zip` only for embedded cross-builds from Linux.

The project keeps the module path `aionwg` and replaces WireGuard with the vendored module under `third_party/wireguard-go`.

## First checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Non-Windows builds compile the compatibility entrypoint and do not exercise packet capture.

## Working rules

Keep behavior changes separate from file moves. Preserve Windows build tags and JSON field names. Never commit `.conf`, private keys, `internal/tlscert/key.pem`, generated binaries or release ZIPs. Network and driver changes require an explicit Windows validation note.
