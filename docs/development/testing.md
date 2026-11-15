# Testing

## Pure Go

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

The packet parser, NAT, checksums, routing decisions, process-policy persistence, queues, diagnostics and runtime extraction tests run without a live VPN.

## Windows compilation and tests

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -o dist/aionwg.test.exe .
```

Tests marked `windows` cover Windows ABI, TUI layout, process/socket behavior, runtime tuning and route logic. Running the compiled test binary on Windows is required for WinDivert, Wintun, WFP/BFE and elevated runtime behavior.

## Privileged/integration tests

`embedded_smoke_windows_test.go` and live capture tests require an elevated Windows shell and installed network drivers. They are not part of the unprivileged Linux baseline. Do not report a cross-compile as proof of packet capture or WFP filter installation.
