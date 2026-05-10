# qssm-local-verifier v1.0.0 â€” FROZEN FOR INSTITUTIONAL USE

**Crate:** `qssm-local-verifier`
**Version:** 1.0.0
**Freeze date:** 2026-04-18
**License:** BUSL-1.1

---

## Scope

Layer 4 Verifier for the QSSM zero-knowledge stack.

- **Role:** Offline proof verification â€” resolves templates from the standard gallery, then delegates to `zk_api::verify` (Layer 5)
- **Security model:** Convenience wrapper only â€” holds no secrets, performs no cryptographic operations, adds no custom verification logic
- **Architectural rule:** This crate depends only on `qssm-api` (Layer 5 facade) and `qssm-templates` (template gallery). No Layer 1/2/3 dependencies.

## Freeze Contract

This crate is **frozen** at v1.0.0. The following invariants are locked:

1. **Public API surface** â€” `verify_proof_offline()`, `verify_proof_with_template()`, `VerifyError` (with `UnknownTemplate` and `Zk` variants). Re-exports: `Proof`, `ProofContext`, `ZkError`, `QssmTemplate`. Additions are allowed; removals require a major version bump.
2. **Dependency boundary** â€” qssm-local-verifier depends only on `qssm-api`, `qssm-templates`, `serde_json`, `thiserror`. No Layer 1/2/3 crate dependencies.
3. **No verification logic** â€” all cross-engine verification is delegated to `zk_api::verify`. This crate adds only template resolution.
4. **`VerifyError` is `#[non_exhaustive]`** â€” new variants may be added in minor releases.

Any change that violates these invariants requires a new security review and a major version bump.

## What Was Hardened for v1.0.0

Four improvements were implemented for the freeze:

### 1. Gadget MS bridge vs this crate’s MS verify

Historically, a cleartext MS `LatticePolyOp` adapter lived in the gadget tree under `ms_ghost_mirror.rs`. **Current gadget policy:** the active MS bridge is **`MsPredicateOnlyV2BridgeOp`** (`verify_predicate_only_v2` + `ms_v2_*` seam observables); the orphan GhostMirror adapter file has been **removed** from `qssm-gadget`.

**Current crate behavior:** packaged proof verification in `src/lib.rs` uses MS v2 predicate-only statement/proof objects and `verify_predicate_only_v2`, aligned with the gadget bridge seam.

### 2. `#![forbid(unsafe_code)]` added

Crate-wide prohibition on unsafe code.

### 3. `VerifyError` made `#[non_exhaustive]`

Future error variants can be added without semver break.

### 4. Test hardening

Added 5 new adversarial tests (explicit template round-trip, tampered MS root, wrong binding context, wrong claim, tampered binding entropy) bringing total to 7.

## Verification Evidence

| Check | Result |
|-------|--------|
| `cargo test -p qssm-local-verifier` | **7/7 passed** (2 roundtrip + 5 adversarial) |
| `cargo check` on workspace | **Clean** |
| `#![forbid(unsafe_code)]` | **Present** |
| `VerifyError` `#[non_exhaustive]` | **Present** |
| Layer 1/2/3 dependencies | **None** (only zk-api, template-lib, serde_json, thiserror) |
| `SECURITY_CHECKLIST.md` | **Rev 1 â€” all boxes checked** |

## Dependencies (pinned at freeze)

| Crate | Version | Purpose |
|-------|---------|---------|
| `qssm-api` | path (workspace) | Cross-engine verification delegation |
| `qssm-templates` | path (workspace) | Template gallery resolution |
| `serde_json` | workspace | Claim type (`serde_json::Value`) |
| `thiserror` | workspace | `VerifyError` derive |

Dev-only: `qssm-utils` (test helpers).

## File Inventory

```
src/
  lib.rs                  â€” verify_proof_offline, verify_proof_with_template, VerifyError, 7 tests
SECURITY_CHECKLIST.md     â€” Rev 1, all items checked
FREEZE.md                 â€” This file
Cargo.toml                â€” v1.0.0
```

---

**This crate is frozen. Do not modify without a security review.**
