# qssm-local-prover

Internal deterministic proving crate for the QSSM workspace.

This crate is frozen and security-reviewed, but it is not a user-facing API.
`qssm-api` is the only user-facing API boundary.

## What This Crate Does

- Runs the internal prove pipeline for the canonical MS v2 predicate-only path
  and LE proof composition
- Derives all internal secrets deterministically from `entropy_seed` and
  `binding_ctx`
- Produces internal proof artifacts consumed by workspace crates

## Boundary and Canonical Protocol Notes

- `qssm-local-prover` is an internal implementation crate.
- `qssm-api` is the only public boundary for applications.
- MS v2 predicate-only is the canonical active MS path.
- Legacy GhostMirror/v1 is removed from active code.

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
