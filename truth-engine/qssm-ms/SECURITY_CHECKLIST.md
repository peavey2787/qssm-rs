QSSM-MS v2 Security Checklist

Scope: `truth-engine/qssm-ms` (internal crate, product boundary is `qssm-api`)

1. API and boundary

- [x] `#![forbid(unsafe_code)]` remains enabled.
- [x] Public surface is v2-only (`commit_value_v2`, predicate-only prove/verify/simulate APIs and v2 wire types).
- [x] Legacy GhostMirror v1 API (`commit`/`prove`/`verify`, `GhostMirrorProof`, `Root`, `Salts`) removed.
- [x] `qssm-ms` is documented as internal; user-facing API boundary is `qssm-api`.

2. Cryptographic invariants

- [x] Domain labels and query labels are unchanged.
- [x] XOF framing (`v2_xof`) remains unchanged.
- [x] Scalar/point encoding and canonical decoding checks are unchanged.
- [x] Query/challenge split checks for bitness and comparison remain unchanged.
- [x] Statement/proof transcript-digest behavior remains unchanged.

3. Adversarial coverage

- [x] `unit_tests/predicate_only_v2_adversarial.rs` covers digest tampering, challenge tampering, response tampering, wrong target/context, and proof-count mismatch.
- [x] Fuzz target is `fuzz/fuzz_targets/verify_predicate_only_v2.rs`.

4. Module hygiene

- [x] `src/v2.rs` split into `src/v2/{types,protocol,internals,wire_constructors,tests}.rs`.
- [x] Each touched Rust source file in this stage is below 500 lines.
