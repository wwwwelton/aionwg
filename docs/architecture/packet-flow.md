# Packet flow

## Outbound

```mermaid
sequenceDiagram
    participant App as Selected process
    participant WD as WinDivert NETWORK
    participant P as Classifier/NAT/MSS
    participant T as split TUN
    participant WG as WireGuard-go
    participant Peer as VPN/WARP peer

    App->>WD: outbound IP packet
    WD->>P: packet + divert address
    P->>P: classify process, policy, destination and family
    P->>P: apply bypass, NAT, checksums and MSS rules
    P->>T: inject packet into tunnel path
    T->>WG: encrypted transport payload
    WG->>Peer: UDP WireGuard transport
```

`BYPASS` returns traffic to the normal Windows path. `BLOCK` is enforced by Native WFP ALE filters when a full executable identity can be resolved. WFP `PERMIT` is not used as a fake route redirect.

## Inbound

```mermaid
sequenceDiagram
    participant Peer as VPN/WARP peer
    participant WG as WireGuard-go
    participant T as split TUN
    participant P as Inbound NAT/diagnostics
    participant WD as WinDivert NETWORK
    participant App as Original process

    Peer->>WG: encrypted UDP transport
    WG->>T: decrypted IP packet
    T->>P: inbound packet
    P->>P: match NAT, restore addresses, checksums and ICMP state
    P->>WD: reinject toward the original interface
    WD->>App: packet delivered
```

The Wintun adapter used by the DPS meter is a diagnostic mirror. It is not the primary tunnel interface.

## Buffer and shutdown rules

- Packet buffers are owned by the capture or tunnel queue until injection completes.
- Bounded queues may drop work and expose counters instead of blocking the packet path.
- Shutdown closes capture, tunnel and monitor handles, signals queues, waits for goroutines, then removes policy objects.
- Existing flows may keep their authorization after an ALE decision; changing a rule does not retroactively terminate every flow.
