LOCAL-VERIFIER "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Layer 4 — The Verifier (`truth-engine/local-verifier`)
**Role:** Offline proof verification — resolves templates, delegates to `zk_api::verify`
**Date:** 2026-04-18 (rev 1 — v1.0.0 freeze)

---

**CONTRACT:** Any change that violates or bypasses an item in this checklist
requires a new security review and version bump.

---

1. PUBLIC SURFACE & BOUNDARY SAFETY

Public API Exposure

[x] `#![forbid(unsafe_code)]` on `lib.rs`. No `unsafe` blocks possible in the crate.

[x] Public API is exactly: `verify_proof_offline()`, `verify_proof_with_template()`, `VerifyError`. Plus re-exports: `Proof`, `ProofContext`, `ZkError` (from `zk-api`), `QssmTemplate` (from `template-lib`).

[x] No internal modules. The crate is a single `lib.rs` file — no hidden plumbing.

[x] `VerifyError` is `#[non_exhaustive]` — new variants can be added in minor releases without breaking downstream `match` arms.

Architectural Purity

[x] No Layer 1 (LE), Layer 2 (MS), or Layer 3 (gadget) dependencies. The verifier depends only on `zk-api` (Layer 5 facade) and `template-lib` (template gallery). Layer separation is enforced by the dependency graph.

[x] `MsGhostMirrorOp` (a `LatticePolyOp` implementation) was relocated to `qssm-gadget` (Layer 3) at v1.1.0 before this freeze. All circuit-composition logic lives in its proper layer.

Error Handling

[x] All failures return typed errors — `VerifyError` or `ZkError`. No panics reachable from any exported path.

[x] No `unwrap()` or `expect()` in any production path. Template not found → `VerifyError::UnknownTemplate`. ZK failure → `VerifyError::Zk(ZkError)`.

[x] No secret material in any error variant. `UnknownTemplate` carries only the template ID string. `Zk` wraps `ZkError` which carries only public error descriptions.

2. VERIFICATION LOGIC

[x] `verify_proof_offline()` — resolves template by ID from the standard gallery, then delegates to `zk_api::verify`. Two operations, no custom logic.

[x] `verify_proof_with_template()` — direct delegation to `zk_api::verify` with an explicit template. Zero custom logic.

[x] The actual cross-engine verification (MS → truth digest → LE lattice check) is performed entirely by `zk_api::verify`. This crate adds no verification logic of its own — it is a convenience wrapper providing template resolution.

3. SECURITY MODEL

[x] The verifier holds no secrets. `ProofContext` contains a `VerifyingKey` (public) and a shared seed (public). `Proof` contains only public proof artifacts.

[x] `binding_ctx` is passed by value (`[u8; 32]`) — no reference lifetime issues, no aliasing.

[x] Template resolution is a linear scan of a small static gallery — no injection risk, no external I/O.

[x] No timing side-channels relevant to this crate — it holds no secrets and performs no comparisons on secret data. All CT comparisons happen in the downstream `qssm-ms` and `qssm-le` crates.

4. TEST COVERAGE

[x] `offline_round_trip` — prove → verify via template gallery (happy path).
[x] `unknown_template_rejected` — non-existent template ID → `VerifyError::UnknownTemplate`.
[x] `verify_with_explicit_template_round_trip` — prove → verify via explicit template (happy path).
[x] `tampered_ms_root_rejected` — flipped byte in `ms_root` → verification error.
[x] `wrong_binding_context_rejected` — different `binding_ctx` → verification error.
[x] `wrong_claim_rejected` — claim below template threshold → predicate error.
[x] `tampered_binding_entropy_rejected` — flipped byte in `binding_entropy` → verification error.

5. FINAL CERTIFICATION

[x] No `unsafe` code (`#![forbid(unsafe_code)]`)
[x] Single-file crate — no hidden modules or internal plumbing
[x] Pure Layer 4 — no Layer 1/2/3 dependencies
[x] All error types `#[non_exhaustive]`
[x] All failures return typed errors — no panics
[x] No secret material in errors or state
[x] 7 tests passing (2 roundtrip + 5 adversarial)
[x] All downstream/upstream crates compile clean

All boxes checked — local-verifier v1.0.0 Layer 4 is bank-grade and frozen for institutional use.
