# TUI controls

The existing shortcuts remain authoritative:

| Key | Action |
|---|---|
| `Enter` / `c` | Connect or disconnect selected tunnel |
| `↑` / `↓`, `k` / `j` | Navigate |
| `i` | Import profile |
| `p` | Process rules |
| `w` / `l` | WFP mode and selected applications |
| `s` / `n` | Full tunnel and tunnel DNS |
| `b` / `v` / `t` | Best route, endpoint, ping target |
| `m` | DPS mirror |
| `u` / `r` / `f` | UDP duplicate, ratio, force |
| `o` / `a` | Newest outbound/inbound scheduling |
| `x` / `g` | Self-test and diagnostics |
| `e` | Official WireGuard export |
| `d` | Remove profile |
| `h` | Opt-in WARP multipath |
| `q` / `Ctrl+C` | Exit |

Modern navigation is additive: `F1`–`F10`, `Ctrl+K`, `/`, `?`, `Esc`, `Tab` and `Shift+Tab` do not replace the existing actions. The WFP panel distinguishes policy backend, packet backend, BFE session and filter status.
