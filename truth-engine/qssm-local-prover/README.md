# qssm-local-prover

Internal deterministic proving crate for the QSSM workspace.

This crate is frozen and security-reviewed, but it is not the public SDK entry
point. Application code should treat it as an internal proving component that
works alongside `qssm-api` types.

## What This Crate Does

- Runs the prove pipeline: predicate check -> MS commit/prove -> truth binding
  -> LE proof
- Derives all internal secrets deterministically from `entropy_seed` and
  `binding_ctx`
- Returns `qssm_api::Proof` for downstream wire-format or verification use

## Contributor Rules

- Do not change key schedule order, domain tags, proof construction order, or
  zeroization points without a new freeze review.
- Keep secret-bearing locals scrubbed exactly as documented in
  `SECURITY_CHECKLIST.md`.
- Do not widen the public surface casually. The sole export is `prove()`.

## Verification

```sh
cargo test -p qssm-local-prover
```
