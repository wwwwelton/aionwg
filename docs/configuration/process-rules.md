# Process rules

Legacy syntax remains compatible:

```text
Aion2.exe, Discord.exe=BYPASS, helper.exe=BLOCK, browser.exe=DEFAULT
```

Unqualified names default to `TUNNEL`. JSON persistence stores the normalized policy and may include an optional `path` for Native WFP App ID resolution.

Policy ownership is intentionally split:

- Native WFP: `BLOCK` authorization filters only.
- WinDivert classifier: `TUNNEL`, `BYPASS`, `DEFAULT`, process ownership and packet routing.

Do not use `PERMIT` filters as a substitute for route selection. A permit decision does not force a process through Wintun or WireGuard.
