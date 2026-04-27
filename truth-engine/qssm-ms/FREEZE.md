# QSSM-MS Freeze (v2-only)

**Crate:** `qssm-ms`  
**Status:** internal implementation crate, frozen around MS v2 behavior  
**Product boundary:** `qssm-api` (not `qssm-ms`)

## Scope

`qssm-ms` now contains only the MS v2 predicate-only flow:

- value commitment generation
- predicate-only prover/verifier
- programmed-oracle simulator + verification path
- wire reconstruction constructors for decoded fields

Legacy GhostMirror v1 API and implementation were removed from this crate.

## Locked Invariants

The following are frozen unless a new security review explicitly approves a change:

1. **MS v2 cryptographic semantics** (`commit_value_v2`, `prove_predicate_only_v2`, `verify_predicate_only_v2`).
2. **Domain labels / transcript labels** used by v2 query and challenge derivations.
3. **XOF framing and scalar/point derivation behavior**.
4. **Wire behavior and reconstruction layout** (`wire_constructors`, `from_wire_parts` constraints).
5. **Observable contract** consumed by gadget/proofs/local-verifier.

## Current File Inventory

```text
src/
  lib.rs
  error.rs
  v2/
    mod.rs
    types.rs
    protocol.rs
    internals.rs
    wire_constructors.rs
    tests.rs
unit_tests/
  predicate_only_v2_adversarial.rs
fuzz/
  fuzz_targets/
    verify_predicate_only_v2.rs
```
