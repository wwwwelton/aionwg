# Process policy

A process rule is persisted as a name, optional full path, and one of:

- `TUNNEL`: classify and forward through the existing packet backend.
- `BYPASS`: keep the process on the normal Windows route.
- `BLOCK`: install Native WFP ALE block filters for the executable App ID.
- `DEFAULT`: follow the configured/default classification behavior.

## Identity

Native WFP uses `FwpmGetAppIdFromFileName0` and `FWPM_CONDITION_ALE_APP_ID`. A basename is accepted only when one unique running process provides the full path. Ambiguous or unavailable identities are rejected instead of installing a rule for the wrong executable.

The existing packet classifier continues to use process ownership, child inheritance and IP Helper fallbacks. Internal exclusions for the AionWG transport, VPN endpoints, local networks and multicast are not user policy rules and must remain protected.

## Compatibility

Legacy process input such as `Aion2.exe, Discord.exe=BYPASS` remains accepted. JSON settings preserve the existing `process_rules` field and add an optional `path` field without renaming existing keys.

The default Aion process names are migration defaults only. They are not the policy engine's identity mechanism and should be replaced by explicit user selection when a title uses a different executable.
