# Windows runtime validation

Validated on 2026-11-15 from WSL against the attached Windows host:

- Windows 11 Pro, build 26300, AMD64.
- Native Windows Go `go1.27.4`.
- Native Windows `go vet ./...`: passed after the package migration.
- Native Windows `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/aionwg`: passed; release executable was 10,352,640 bytes.
- Current release launch: `dist/AionWG.exe` started with `Start-Process -Verb RunAs`; PID 38248 was observed and left running for manual UAC/TUI traffic validation.

The Linux/WSL checks also passed:

```text
go test ./...
go test -race ./...
go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' ./cmd/aionwg
```

- The current log showed real process traffic (`fluxos=2`), direct RTT around 20–25 ms and no injection errors, but `handshake=nunca`; the tunnel was not yet connected.
- Still not validated: importing and connecting the supplied WARP profile, a successful WireGuard handshake, native WFP filter installation under a selected process, Wintun packet traffic, loss/jitter under load and real game traffic. Continue manually in the running TUI with `[i]`, `Enter`, diagnostics `[g]` and `[q]` only after the test.
