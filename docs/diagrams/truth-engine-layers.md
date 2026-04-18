# Truth Engine — Six-Layer Stack

```mermaid
graph TB

    %% Core Truth Engine Stack
    subgraph Truth_Engine_Stack
        L6["Layer 6: qssm-api Public API & wire format"]
        L5["Layer 5: qssm-local-verifier Deterministic yes/no verification"]
        L4["Layer 4: qssm-local-prover + qssm-entropy Consumes entropy, builds proof artifacts"]
        L3["Layer 3: qssm-gadget Recursive bridge (LE ↔ MS binding)"]
        L2["Layer 2: qssm-ms Mirror-Shift Engine B (integrity engine)"]
        L1["Layer 1: qssm-le Lattice Engine A (mathematical foundation)"]
    end

    %% Downward-only dependencies
    L6 --> L5
    L5 --> L4
    L4 --> L3
    L3 --> L2
    L2 --> L1

    %% External mathematical foundations
    BLAKE3["BLAKE3 + Merkle tree"]
    RING["Ring R_q = Z_q[X]/(X^256+1)"]

    L2 --> BLAKE3
    L1 --> RING

    %% Supporting Crates
    subgraph Supporting_Crates
        TEMPLATES["qssm-templates Template gallery & predicates"]
        UTILS["qssm-utils Hashing, domain separation"]
    end

    %% Template usage (dashed = non-layer support)
    L6 -.-> TEMPLATES
    L5 -.-> TEMPLATES
    L4 -.-> TEMPLATES

    %% Utils used by engines
    L3 -.-> UTILS
    L2 -.-> UTILS
    L1 -.-> UTILS

```

## Layer Responsibilities

| Layer | Crate | Role |
|-------|-------|------|
| 1 | `qssm-le` | Lattice-Engine A, the mathematical foundation of the stack; currently frozen and complete |
| 2 | `qssm-ms` | Mirror-Shift Engine B, the integrity engine and truth binder |
| 3 | `qssm-gadget` | The recursive bridge that allows Engine A to verify Engine B; currently frozen and complete |
| 4 | `qssm-local-prover` + `qssm-entropy` | Consumes entropy and produces a complete proof artifact |
| 5 | `qssm-local-verifier` | The local verifier that returns the final yes or no decision |
| 6 | `qssm-api` | The public API and wire format: how the world talks to the machine |
```