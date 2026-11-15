# Windows runtime validation

Validated on 2026-11-15 from WSL against the attached Windows host:

- Windows 11 Pro, build 26300, AMD64.
- Native Windows Go `go1.27.4`.
- Native Windows `go vet ./...`: passed.
- Native Windows `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" .`: passed; test executable was 10,337,280 bytes.
- UAC launch: the test executable was started with `Start-Process -Verb RunAs`; a running AionWG process was observed and then stopped after the smoke check.

The Linux/WSL checks also passed:

```text
go test ./...
go test -race ./...
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' .
```

Not validated in this smoke run: an interactive TUI session, an imported WARP profile, real WireGuard handshake, WinDivert packet interception, Wintun traffic, native WFP filter installation under a selected process, loss/jitter under load, or real game traffic. Those require an interactive elevated Windows session and should be repeated with a non-production test profile.
