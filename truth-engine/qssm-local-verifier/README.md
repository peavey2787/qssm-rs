# qssm-local-verifier

Internal offline-verifier convenience crate for the QSSM workspace.

This crate is frozen, holds no secrets, and adds no cryptographic logic of its
own. It exists to resolve templates and delegate verification to `qssm-api`.

## What This Crate Does

- Resolves built-in templates by ID
- Wraps `qssm_api::verify()` behind a single offline entry point
- Re-exports `Proof`, `ProofContext`, `ZkError`, and `QssmTemplate`

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
