# Contributing to AionWG

## Before changing code

Read the [architecture overview](docs/architecture/overview.md), [testing guide](docs/development/testing.md) and [security model](docs/security/threat-model.md). Confirm the working tree is clean and keep unrelated local profiles, binaries and generated artifacts out of the change.

## Development

Use the Go version declared by `go.mod`. Run:

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

For Windows-specific changes, also run the Windows cross-build and, when available, the relevant tests in an elevated Windows 11 x64 environment. Do not claim a driver, WFP/BFE filter or live packet test based only on cross-compilation.

## Change boundaries

- Preserve JSON field names, profile formats, TUI shortcuts and executable/archive names.
- Keep packet hot-path changes separate from documentation and mechanical moves.
- Preserve `//go:build` constraints and embedded asset integrity.
- Do not change WireGuard keys, MTU defaults, WARP multipath defaults or traffic policy silently.
- Never add `.conf`, private keys, PFX files, logs, binaries or generated ZIPs.
- Add a deterministic regression test for non-trivial behavior changes.

## Pull requests

Use a focused branch and a Conventional Commit subject. Describe the behavior before and after, the exact checks run, Windows/elevation requirements and any remaining runtime validation. For source moves, include the old path, new path, imports affected and compatibility risk.

Network, driver, native API and security changes require reviewer attention from someone able to test Windows. Avoid bundling a broad package migration with a packet behavior change.

## Reporting problems

Use the issue templates. Redact private keys, VPN profiles, public IPs and sensitive logs. Security issues follow [`SECURITY.md`](SECURITY.md), not a public issue.
