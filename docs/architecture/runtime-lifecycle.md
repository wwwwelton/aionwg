# Runtime lifecycle

```mermaid
stateDiagram-v2
    [*] --> Elevate
    Elevate --> RuntimeReady: elevated and assets verified
    RuntimeReady --> TUI: prepare runtime and DLL search path
    TUI --> EngineStarting: connect profile
    EngineStarting --> Connected: tunnel, capture and monitors ready
    EngineStarting --> TUI: error with cleanup
    Connected --> TUI: disconnect
    TUI --> ShuttingDown: quit or fatal error
    Connected --> ShuttingDown: quit or fatal error
    ShuttingDown --> [*]: stop loops, close handles, remove WFP objects
```

Embedded builds verify and extract native files into a content-addressed directory under `Program Files\\AionWG-Runtime`. DLL loading is restricted to the verified runtime directory and Windows system directories. External builds use files beside the executable and are less self-contained.

The current entrypoint still lives in the root `main` package. The package migration is tracked in ADR 0001 and must preserve this lifecycle order.
