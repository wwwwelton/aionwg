# Process manager

The current TUI process editor persists executable names and policy values. It can select running processes for WFP observation and preserve rules for processes that are currently closed.

Native WFP `BLOCK` rules require a full executable path or a unique running basename. This prevents an ambiguous `game.exe` rule from blocking the wrong application. `TUNNEL` and `BYPASS` remain enforced by the existing packet classifier; a WFP permit filter cannot redirect traffic to WireGuard.

The planned package split will move enumeration and ownership into `internal/process` and policy resolution into `internal/policy`. Until that extraction is complete, behavior remains in the root package to avoid duplicating precedence rules.
