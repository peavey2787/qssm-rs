# zk-api v1.0.0 — Security Checklist

**Crate:** `zk-api` (Layer 5 — The API)
**Revision:** 1

---

## Public Surface

- [x] `#![forbid(unsafe_code)]` — crate-wide
- [x] Minimal public API — `prove`, `verify`, `ProofContext`, `Proof`, `ProofBundle`, `WireFormatError`, `ZkError`, `PROTOCOL_VERSION`, `template_lib` re-export
- [x] `ZkError` is `#[non_exhaustive]` — new variants can be added without semver break
- [x] `WireFormatError` is `#[non_exhaustive]` — new variants can be added without semver break
- [x] `Proof` is `#[non_exhaustive]` — prevents external struct-literal construction
- [x] `ProofBundle` is `#[non_exhaustive]` — prevents external struct-literal construction
- [x] `ProofContext.vk` is `pub(crate)` — only accessible via `vk()` accessor

## Architectural Purity

- [x] No Layer 1/2/3 types in the public API — all lower-layer types are encapsulated
- [x] `prove()` orchestrates the deterministic pipeline: predicate → MS → truth binding → LE
- [x] `verify()` delegates entirely: predicate → MS verify → cross-engine rebinding → LE verify
- [x] `derive_le_witness()` is SDK-level key schedule (not protocol logic) — domain tag `DOMAIN_SDK_LE_WITNESS`
- [x] No entropy re-exports — `qssm-he` removed from dependencies; callers depend on it directly
- [x] `SovereignProofBundle` alias removed — single canonical type `ProofBundle`
- [x] Shared `MS_CONTEXT_TAG` const — no duplicated magic strings between prove and verify

## Error Handling

- [x] All failures return typed `ZkError` or `WireFormatError` — no panics
- [x] No `unwrap()` or `expect()` in production code
- [x] `#[from]` only on `PredicateError` — all other error mappings are explicit

## Wire Format

- [x] `ProofBundle` versioned — `version` + `protocol_version` fields, checked on deserialization
- [x] `#[serde(deny_unknown_fields)]` — rejects JSON with unknown fields (security)
- [x] All hex fields validated on deserialization (length, encoding)
- [x] Polynomial coefficient counts validated (must be exactly `N = 256`)
- [x] MS proof fields validated via `GhostMirrorProof::new`

## Security Model

- [x] No secrets held — `ProofContext` contains only public key material
- [x] Deterministic pipeline — same inputs always produce same outputs (no internal RNG)
- [x] Cross-engine binding enforced in `verify()` — recomputes truth digest from MS transcript

## Test Coverage

- [x] **18 unit tests** — round-trip, 5 adversarial, 6 wire format, 2 injectivity/preservation, 1 JSON schema, 1 witness derivation, 1 accessor
- [x] **3 compile-fail tests** (trybuild) — non-exhaustive `ZkError`, non-exhaustive `WireFormatError`, entropy not re-exported
- [x] **1 doc-test** — quick start example compiles

## Dependencies (pinned at freeze)

| Crate | Purpose |
|-------|---------|
| `qssm-le` | Layer 1 lattice engine |
| `qssm-ms` | Layer 2 mirror-shift engine |
| `qssm-gadget` | Layer 3 truth binding gadgets |
| `qssm-utils` | Hashing utilities, domain separators |
| `template-lib` | Predicate template gallery |
| `serde` | Serialization |
| `serde_json` | JSON claim type |
| `thiserror` | Error derive |
| `hex` | Hex encoding for wire format |

Dev-only: `trybuild` (compile-fail tests).

## Final Certification

- [x] All boxes above checked
- [x] `cargo test -p zk-api` — 22/22 passed (18 unit + 3 compile-fail + 1 doc-test)
- [x] `cargo check` — clean compilation
- [x] Ready for institutional freeze at v1.0.0
