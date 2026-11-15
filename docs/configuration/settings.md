# Settings

Persistent settings are stored in `%APPDATA%\\AionWG\\settings.json` with mode `0600` where the platform supports it. The current schema version is `3`.

Existing keys include process lists/rules, last profile, ping target, mirror settings, UDP duplication and ordering, DNS/full-tunnel modes, WFP application selection, endpoint monitoring, WARP multipath and CWB search.

Settings migrations are in `store.go`. They add missing defaults and preserve existing values. A future package migration must keep JSON names and version handling stable; do not rename fields without a migration and backup plan.
