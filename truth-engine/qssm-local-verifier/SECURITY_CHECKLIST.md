qssm-local-verifier "BANK-GRADE" PRODUCTION READINESS CHECKLIST

**Scope:** Layer 4 â€” The Verifier (`truth-engine/qssm-local-verifier`)
**Role:** Offline proof verification â€” resolves templates, delegates to `zk_api::verify`
**Date:** 2026-04-18 (rev 1 â€” v1.0.0 freeze)

---

**CONTRACT:** Any change that violates or bypasses an item in this checklist
requires a new security review and version bump.

---

1. PUBLIC SURFACE & BOUNDARY SAFETY

Public API Exposure

[x] `#![forbid(unsafe_code)]` on `lib.rs`. No `unsafe` blocks possible in the crate.

[x] Public API is exactly: `verify_proof_offline()`, `verify_proof_with_template()`, `VerifyError`. Plus re-exports: `Proof`, `ProofContext`, `ZkError` (from `qssm-api`), `QssmTemplate` (from `qssm-templates`).

[x] No internal modules. The crate is a single `lib.rs` file â€” no hidden plumbing.

[x] `VerifyError` is `#[non_exhaustive]` â€” new variants can be added in minor releases without breaking downstream `match` arms.

Architectural Purity

[x] No Layer 1 (LE), Layer 2 (MS), or Layer 3 (gadget) dependencies. The verifier depends only on `qssm-api` (Layer 5 facade) and `qssm-templates` (template gallery). Layer separation is enforced by the dependency graph.

[x] `MsGhostMirrorOp` (a `LatticePolyOp` implementation) was relocated to `qssm-gadget` (Layer 3) at v1.1.0 before this freeze. All circuit-composition logic lives in its proper layer.

Error Handling

[x] All failures return typed errors â€” `VerifyError` or `ZkError`. No panics reachable from any exported path.

[x] No `unwrap()` or `expect()` in any production path. Template not found â†’ `VerifyError::UnknownTemplate`. ZK failure â†’ `VerifyError::Zk(ZkError)`.

[x] No secret material in any error variant. `UnknownTemplate` carries only the template ID string. `Zk` wraps `ZkError` which carries only public error descriptions.

2. VERIFICATION LOGIC

[x] `verify_proof_offline()` â€” resolves template by ID from the standard gallery, then delegates to `zk_api::verify`. Two operations, no custom logic.

[x] `verify_proof_with_template()` â€” direct delegation to `zk_api::verify` with an explicit template. Zero custom logic.

[x] The actual cross-engine verification (MS â†’ truth digest â†’ LE lattice check) is performed entirely by `zk_api::verify`. This crate adds no verification logic of its own â€” it is a convenience wrapper providing template resolution.

3. SECURITY MODEL

[x] The verifier holds no secrets. `ProofContext` contains a `VerifyingKey` (public) and a shared seed (public). `Proof` contains only public proof artifacts.

[x] `binding_ctx` is passed by value (`[u8; 32]`) â€” no reference lifetime issues, no aliasing.

[x] Template resolution is a linear scan of a small static gallery â€” no injection risk, no external I/O.

[x] No timing side-channels relevant to this crate â€” it holds no secrets and performs no comparisons on secret data. All CT comparisons happen in the downstream `qssm-ms` and `qssm-le` crates.

4. TEST COVERAGE

[x] `offline_round_trip` â€” prove â†’ verify via template gallery (happy path).
[x] `unknown_template_rejected` â€” non-existent template ID â†’ `VerifyError::UnknownTemplate`.
[x] `verify_with_explicit_template_round_trip` â€” prove â†’ verify via explicit template (happy path).
[x] `tampered_ms_root_rejected` â€” flipped byte in `ms_root` â†’ verification error.
[x] `wrong_binding_context_rejected` â€” different `binding_ctx` â†’ verification error.
[x] `wrong_claim_rejected` â€” claim below template threshold â†’ predicate error.
[x] `tampered_binding_entropy_rejected` â€” flipped byte in `binding_entropy` â†’ verification error.

5. FINAL CERTIFICATION

[x] No `unsafe` code (`#![forbid(unsafe_code)]`)
[x] Single-file crate â€” no hidden modules or internal plumbing
[x] Pure Layer 4 â€” no Layer 1/2/3 dependencies
[x] All error types `#[non_exhaustive]`
[x] All failures return typed errors â€” no panics
[x] No secret material in errors or state
[x] 7 tests passing (2 roundtrip + 5 adversarial)
[x] All downstream/upstream crates compile clean

All boxes checked â€” qssm-local-verifier v1.0.0 Layer 4 is bank-grade and frozen for institutional use.
