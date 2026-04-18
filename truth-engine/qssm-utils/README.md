# qssm-utils

Internal utility crate for the QSSM truth-engine workspace.

This crate is frozen for institutional use, but it is still an internal
building block. External consumers should use the facade crates instead of
depending on `qssm-utils` directly.

## What Lives Here

- Versioned BLAKE3 domain tags
- `blake3_hash()` and `hash_domain()`
- `PositionAwareTree` and `merkle_parent()`
- Entropy screening helpers: `verify_density()`,
  `validate_entropy_distribution()`, and `validate_entropy_full()`

## Contributor Rules

- Do not change domain tags, Merkle proof order, padding behavior, or entropy
  gate semantics without a new audit cycle.
- Keep public error enums `#[non_exhaustive]`.
- Do not add secret-handling APIs here casually. This crate currently has no
  zeroization or constant-time requirements because it holds no secrets.
- Treat `FREEZE.md` and `SECURITY_CHECKLIST.md` as the authoritative review
  record for frozen behavior.

## Verification

```sh
cargo test -p qssm-utils --all-features
```
