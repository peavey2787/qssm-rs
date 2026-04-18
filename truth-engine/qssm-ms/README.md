# qssm-ms

Internal Mirror-Shift engine crate for the QSSM truth-engine workspace.

This crate is frozen for institutional use, but developers still need a short
map of what lives here and what must not move.

## What This Crate Does

- Builds a 128-leaf Ghost-Mirror commitment from deterministic salts and
  binding entropy.
- Produces succinct proofs of the public predicate `value > target`.
- Verifies Merkle opening, Fiat-Shamir binding, and the crossing predicate.

This is not a general-purpose proving system and it is not zero-knowledge.
Both `value` and `target` are verifier-known inputs.

## Public Surface

Primary types and functions are re-exported from [src/lib.rs](src/lib.rs):

- `commit(seed, binding_entropy)`
- `prove(value, target, salts, binding_entropy, context, binding_context)`
- `verify(root, proof, binding_entropy, value, target, context, binding_context)`
- `Root`
- `GhostMirrorProof`
- `Salts`
- `MsError`

## Internal Layout

- [src/lib.rs](src/lib.rs): public facade and proof flow
- [src/core.rs](src/core.rs): rotation and highest-differing-bit logic
- [src/transcript.rs](src/transcript.rs): Fiat-Shamir challenge derivation
- [src/commitment/leaves.rs](src/commitment/leaves.rs): salt derivation and leaf construction
- [src/commitment/tree.rs](src/commitment/tree.rs): Merkle path verification
- [src/error.rs](src/error.rs): stable error surface

## Contributor Rules

- Do not widen the public API casually. This crate is frozen.
- Do not change transcript layout, tree size, path length, domain separators,
  or leaf/salt derivation without a new audit cycle.
- Keep secret-bearing types scrubbed with `zeroize` where applicable.
- Keep proof and root encapsulation intact. Use constructors/accessors instead
  of exposing raw fields.
- Keep verifier comparisons constant-time where they compare digests.

## Verification

Run the crate tests:

```sh
cargo test -p qssm-ms
```

Before changing behavior, review:

- [FREEZE.md](FREEZE.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)

If a change would alter a frozen invariant, stop and treat it as a new review
item rather than a routine refactor.