# qssm-local-verifier

Internal offline-verifier convenience crate for the QSSM workspace.

This crate is frozen, holds no secrets, and is an internal verification
implementation crate in the workspace. It is not a user-facing API.

## What This Crate Does

- Verifies internal proof artifacts for local/offline workspace use
- Performs template/predicate consistency checks for verifier flows
- Exposes internal verifier-facing types for workspace crates

## Boundary and Canonical Protocol Notes

- `qssm-local-verifier` is internal implementation surface.
- `qssm-api` is the only user-facing API boundary.
- MS v2 predicate-only is the canonical active MS path.
- Legacy GhostMirror/v1 is removed from active code.

## Contributor Rules

- Keep this crate a thin wrapper. Do not add Layer 1/2/3 verification logic.
- Keep the dependency boundary narrow: `qssm-api`, `qssm-templates`,
  `serde_json`, `thiserror`.
- If behavior changes beyond template resolution or error wrapping, treat it as
  a new review item.

## Verification

```sh
cargo test -p qssm-local-verifier
```
