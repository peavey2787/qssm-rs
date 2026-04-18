# local-verifier v1.0.0 — FROZEN FOR INSTITUTIONAL USE

**Crate:** `local-verifier`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 4 Verifier for the QSSM zero-knowledge stack.

- **Role:** Offline proof verification — resolves templates from the standard gallery, then delegates to `zk_api::verify` (Layer 5)
- **Security model:** Convenience wrapper only — holds no secrets, performs no cryptographic operations, adds no custom verification logic
- **Architectural rule:** This crate depends only on `zk-api` (Layer 5 facade) and `template-lib` (template gallery). No Layer 1/2/3 dependencies.

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Public API surface** — `verify_proof_offline()`, `verify_proof_with_template()`, `VerifyError` (with `UnknownTemplate` and `Zk` variants). Re-exports: `Proof`, `ProofContext`, `ZkError`, `QssmTemplate`. Additions are allowed; removals require a major version bump.
2. **Dependency boundary** — local-verifier depends only on `zk-api`, `template-lib`, `serde_json`, `thiserror`. No Layer 1/2/3 crate dependencies.
3. **No verification logic** — all cross-engine verification is delegated to `zk_api::verify`. This crate adds only template resolution.
4. **`VerifyError` is `#[non_exhaustive]`** — new variants may be added in minor releases.

Any change that violates these invariants requires a new security review and a major version bump.

## What Was Hardened for v1.0.0

Four improvements were implemented for the freeze:

### 1. `MsGhostMirrorOp` relocated to qssm-gadget (Layer 3)

`ms_verifier.rs` implemented `LatticePolyOp` (a Layer 3 gadget trait) inside Layer 4. This was the only `LatticePolyOp` implementation outside of `qssm-gadget`. It has been relocated to `qssm-gadget/src/circuit/operators/ms_ghost_mirror.rs` (gadget v1.1.0), and `qssm-gadget` + `qssm-ms` dependencies have been removed from local-verifier.

### 2. `#![forbid(unsafe_code)]` added

Crate-wide prohibition on unsafe code.

### 3. `VerifyError` made `#[non_exhaustive]`

Future error variants can be added without semver break.

### 4. Test hardening

Added 5 new adversarial tests (explicit template round-trip, tampered MS root, wrong binding context, wrong claim, tampered binding entropy) bringing total to 7.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p local-verifier` | **7/7 passed** (2 roundtrip + 5 adversarial) |
| `cargo check` on workspace | **Clean** |
| `#![forbid(unsafe_code)]` | **Present** |
| `VerifyError` `#[non_exhaustive]` | **Present** |
| Layer 1/2/3 dependencies | **None** (only zk-api, template-lib, serde_json, thiserror) |
| `SECURITY_CHECKLIST.md` | **Rev 1 — all boxes checked** |

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `zk-api` | path (workspace) | Cross-engine verification delegation |
| `template-lib` | path (workspace) | Template gallery resolution |
| `serde_json` | workspace | Claim type (`serde_json::Value`) |
| `thiserror` | workspace | `VerifyError` derive |

Dev-only: `qssm-utils` (test helpers).

## File Inventory

```
src/
  lib.rs                  — verify_proof_offline, verify_proof_with_template, VerifyError, 7 tests
SECURITY_CHECKLIST.md     — Rev 1, all items checked
FREEZE.md                 — This file
Cargo.toml                — v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
