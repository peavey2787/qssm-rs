# qssm-gadget

**Internal crate** — not a public API. All downstream consumers import via the flat re-export surface in `lib.rs`. **Use the facade API (`truth-engine/api`) instead of depending on this crate directly.**

## Purpose

Degree-2 bit witnesses, MS Merkle Phase 0, BLAKE3 compression gadgets, truth binding, and seam operators for the QSSM proof system.

## Modules (internal)

| Module | Role |
|--------|------|
| `primitives` | Bit manipulation, BLAKE3 compression kernels, entropy anchoring |
| `lattice` | Bridge math for lattice-based polynomial operations |
| `circuit` | R1CS constraint system, binding/handshake, seam operators |
| `merkle` | Merkle path witness verification (depth-7, 128-leaf MS tree) |
| `error` | Unified `GadgetError` enum |

## Security Properties

- `#![forbid(unsafe_code)]` on all modules
- All trait methods return `Result` — no silent fallbacks
- No `debug_assert`, `expect`, or `unwrap` in production paths
- All digest/commitment comparisons use `subtle::ConstantTimeEq` (safe for remote-verifier contexts)
- Secret types (`TruthWitness`, `TruthLimbV2Params`, `EngineABindingInput`) implement `Zeroize`/`ZeroizeOnDrop` with redacted `Debug`
- All modules are `pub(crate)` — public surface is a controlled facade
- Structural validation rejects all-zero critical fields and unauthenticated seam inputs
- `run_diagnostic` gated behind `cfg(test)` / `feature = "diagnostic"`

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `diagnostic` | off | Enables `run_diagnostic` for integration debugging |

## Testing

```sh
cargo test -p qssm-gadget
```

Test suites cover: truth digest golden vectors, Merkle parity, MS roundtrip, engine B binding (seam tamper × 12 fields), merkle adversarial, entropy adversarial, property-based avalanche tests.
