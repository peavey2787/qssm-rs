# qssm-le

Internal lattice engine crate for the QSSM workspace.

This crate is internal-only. It is not intended as a stable external dependency and external consumers should go through the workspace facades instead of importing `qssm-le` directly.

For developers:

- Public API is intentionally narrow and re-exported from `src/lib.rs`.
- `prove_with_witness` stays crate-private; use `prove_arithmetic` from the public surface.
- Security review status and concessions are tracked in `SECURITY_CHECKLIST.md`.

Verification:

```sh
cargo test -p qssm-le
```