# EasyCrypt Import Allowlist (First Pass)

Purpose: define what to import into the first-pass EasyCrypt model to avoid drift, historical noise, and implementation-only detail.

Scope boundary:
- `qssm-api` is the only user-facing API boundary.
- First-pass formalization models canonical protocol/spec surfaces, not product wiring.
- Do not model legacy GhostMirror/v1 paths in first pass.

## Classification

### A) Include in first-pass EasyCrypt model

Canonical specs:
- `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`
- `docs/02-protocol-specs/qssm-zk-theorem-spec.md`
- `docs/02-protocol-specs/spec_layer_contract.md`

Theorem/core code anchors:
- `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_core.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_chain.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_graph.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_prob.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/core/types_core.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/core/types_theorem.rs`

Simulator code anchors:
- `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators.rs`
- `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators_extra.rs`
- `truth-engine/qssm-proofs/src/shared/fiat_shamir.rs`

MS v2 code anchors:
- `truth-engine/qssm-ms/src/v2/mod.rs`
- `truth-engine/qssm-ms/src/v2/types.rs`
- `truth-engine/qssm-ms/src/v2/protocol.rs`
- `truth-engine/qssm-ms/src/v2/internals.rs`
- `truth-engine/qssm-ms/src/v2/wire_constructors.rs`

LE FS/params code anchors:
- `truth-engine/qssm-le/src/protocol/commit.rs`
- `truth-engine/qssm-le/src/protocol/params.rs`

Gadget seam/bridge code anchors:
- `truth-engine/qssm-gadget/src/circuit/operators/ms_predicate_v2_bridge.rs`
- `truth-engine/qssm-gadget/src/circuit/operators/engine_a_binding.rs`
- `truth-engine/qssm-gadget/src/circuit/binding_ms_v2.rs`

### B) Reference only (context, not canonical first-pass objects)

- `truth-engine/qssm-proofs/tests/spec_vs_code_fingerprint_test.rs` (sync guard, not model definition)
- `truth-engine/qssm-proofs/tests/parameter_sync.rs` (parameter drift guard)
- crate `README.md` / `FREEZE.md` / `SECURITY_CHECKLIST.md` files (boundary and intent context)
- architecture diagrams and overview docs in `docs/01-architecture/`

### C) Exclude / archive / historical for first pass

- `docs/02-protocol-specs/l1-l2/hybrid-wrapper-schema-v1.md` (historical wrapper schema)
- implementation plans under `docs/02-protocol-specs/implementation-plans/`
- archived hardening notes and one-off migration notes not marked canonical execution/theorem spec
- desktop UI and app wiring (`desktop/`)
- local product wiring crates:
  - `truth-engine/qssm-local-prover/`
  - `truth-engine/qssm-local-verifier/`
  - `truth-engine/qssm-api/` implementation wiring internals
- diagnostics/empirical audit helpers unless needed in later proof phases:
  - `truth-engine/qssm-proofs/src/reduction_zk/audit/`
  - empirical/attempt-report surfaces in simulation support code

## Initial EasyCrypt module plan

## `QssmDomains.ec`
- Rust/spec anchors:
  - `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md` (domains/labels)
  - `truth-engine/qssm-ms/src/v2/internals.rs`
  - `truth-engine/qssm-le/src/protocol/commit.rs`
  - `truth-engine/qssm-gadget/src/circuit/operators/engine_a_binding.rs`
- Definitions to model:
  - domain constants and label constants used in FS/seam hashing
- Assumptions/axioms allowed:
  - collision resistance / ROM abstraction for domain-separated hashes
- Out of scope:
  - API/wire UX concerns, serialization ergonomics

## `QssmTypes.ec`
- Rust/spec anchors:
  - `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md` (transcript fields/order)
  - `truth-engine/qssm-proofs/src/reduction_zk/core/types_core.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/transcript/transcript_model.rs`
- Definitions to model:
  - transcript observable record types and canonical ordering
- Assumptions/axioms allowed:
  - none beyond type well-formedness
- Out of scope:
  - diagnostic/attempt structs and historical transcript wrappers

## `QssmFS.ec`
- Rust/spec anchors:
  - `truth-engine/qssm-ms/src/v2/internals.rs`
  - `truth-engine/qssm-le/src/protocol/commit.rs`
  - `truth-engine/qssm-proofs/src/shared/fiat_shamir.rs`
  - `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`
- Definitions to model:
  - MS bitness/comparison query digests and query-to-scalar
  - LE FS challenge seed and challenge polynomial expansion
- Assumptions/axioms allowed:
  - random-oracle programming assumptions corresponding to A2
- Out of scope:
  - implementation-level optimization details

## `QssmMS.ec`
- Rust/spec anchors:
  - `truth-engine/qssm-ms/src/v2/protocol.rs`
  - `truth-engine/qssm-ms/src/v2/types.rs`
  - theorem references in `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_chain.rs`
- Definitions to model:
  - MS v2 statement/proof relation on verifier-visible surface
  - exact-simulation lemma interfaces (MS-3a/MS-3b/MS-3c)
- Assumptions/axioms allowed:
  - A1 (hash binding), A2 (ROM programmability)
- Out of scope:
  - legacy GhostMirror/v1 APIs and historical wrappers

## `QssmLE.ec`
- Rust/spec anchors:
  - `truth-engine/qssm-le/src/protocol/commit.rs`
  - `truth-engine/qssm-le/src/protocol/params.rs`
  - `truth-engine/qssm-proofs/src/reduction_rejection.rs`
- Definitions to model:
  - LE challenge generation and Set B parameterized algebraic verification surface
- Assumptions/axioms allowed:
  - A4 LE HVZK/ROM replacement bound
- Out of scope:
  - performance-oriented constant-time engineering details

## `QssmSim.ec`
- Rust/spec anchors:
  - `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/simulate/simulators_extra.rs`
  - `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md` ("EasyCrypt formalization surface")
- Definitions to model:
  - `simulate_qssm_transcript` as canonical composed simulator
  - simulator output observables (`SimulatedMsV2Transcript`, `SimulatedLeTranscript`, `SimulatedQssmTranscript`)
- Assumptions/axioms allowed:
  - idealized simulator randomness source assumptions
- Out of scope:
  - `Real*` sampling helpers and attempt/diagnostic report objects

## `QssmGames.ec`
- Rust/spec anchors:
  - `docs/02-protocol-specs/qssm-zk-theorem-spec.md`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_graph.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_core.rs`
- Definitions to model:
  - games `G0`, `G1`, `G2`; transitions and distinguisher advantages
- Assumptions/axioms allowed:
  - standard PPT distinguisher and ROM/game-hopping framework
- Out of scope:
  - CI/testing harness behavior

## `QssmTheorem.ec`
- Rust/spec anchors:
  - `docs/02-protocol-specs/qssm-zk-theorem-spec.md`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_prob.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_chain.rs`
- Definitions to model:
  - composed theorem statement and additive bound
  - assumption mapping A1/A2/A4 to epsilon terms
- Assumptions/axioms allowed:
  - only declared assumptions from theorem spec (A1, A2, A4)
- Out of scope:
  - new undeclared residual epsilon terms

## First-pass import rule

If an artifact conflicts with any item in section A, section A wins.
If an artifact is not clearly canonical and not needed to define theorem/game/simulator objects, keep it out of first pass and add later by explicit decision.
