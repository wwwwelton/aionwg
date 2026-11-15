# ADR 0001: migrate the root package incrementally

- Status: accepted for incremental work
- Date: 2026-11-15

## Decision

Keep the current root `main` package while extracting one dependency boundary at a time. Target packages are listed in `architecture/overview.md`; no empty shells or compatibility aliases will be created.

## Context

The root package combines the TUI, configuration, packet hot path, Windows APIs and engine state. A bulk move into `cmd/aionwg` and many `internal/*` packages would change import ownership, build tags and concrete type relationships in one review. It would also make it easy to accidentally change packet buffer ownership or TUI shortcuts.

## Consequences

Documentation, build tooling and isolated existing packages can be modernized now. Code migration requires package-level contract tests, explicit ownership of contexts/handles and a Windows build after each slice. The root package is technical debt, not a supported public API.
