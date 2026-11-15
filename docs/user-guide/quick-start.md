# Quick start

1. Obtain the source or a release ZIP. Keep `AionWG.exe`, `WinDivert.dll` and `WinDivert64.sys` together for an external build; the standalone build embeds runtime files.
2. Import a WireGuard `.conf` with `[i]`. AionWG validates it and stores a private copy under `%APPDATA%\\AionWG\\configs` with restricted permissions.
3. Select the profile and press `Enter` to connect. The process requests elevation because WinDivert capture requires it.
4. Use `[p]` to select tunnel processes, `[w]`/`[l]` for WFP process selection, `[b]` for conservative endpoint monitoring and `[g]` for diagnostics.
5. Connect before opening the game. Existing connections can remain on their previous path until they reconnect.
6. Press `q` to stop the engine and exit. Shutdown closes capture/tunnel handles and removes runtime Native WFP policy objects.

No setting here changes the global MTU. Use the MTU from the imported profile and validate it on the actual link.
