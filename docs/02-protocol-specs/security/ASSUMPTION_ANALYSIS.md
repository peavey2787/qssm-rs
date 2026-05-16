# Assumption Analysis

This file is the canonical assumption analysis for the current frozen QSSM ZK theorem.
Rust code remains the source of truth.

## Theorem-Level Additive Bound

```text
Adv_QSSM(D) <= epsilon_ms_hash_binding
             + epsilon_ms_rom_programmability
             + epsilon_le
```

Mapped assumptions:
- `A1` -> `epsilon_ms_hash_binding`
- `A2` -> `epsilon_ms_rom_programmability`
- `A4` -> `epsilon_le`

## Theorem Surface Status

The three-term bound above is the exact-zero theorem skeleton consumed by:
- `qssm_main_theorem`

The live companion theorem surfaces also include:
- `qssm_main_theorem_semantic_budget`
- `qssm_main_theorem_parameterized_budget`
- `qssm_main_theorem_realworld_budget`
- `qssm_main_theorem_realworld_concrete_256`
- `qssm_main_theorem_realworld_concrete_256_with_all_reductions`

On the parameterized, abstract real-world, and concrete 256 companion routes:
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- the theorem route therefore pays a charged public-AfterRom-to-canonical-AfterRom landing
- the top additive structure keeps an explicit duplicate MS2 term

```text
epsilon_top = epsilon_MS1 + epsilon_MS2 + epsilon_MS2 + epsilon_LE
```

The duplicate MS2 charge must not be simplified away unless a future theorem proves a zero-cost public-AfterRom-to-canonical-AfterRom landing.

## Concrete 256 Companion Route Status

The EasyCrypt tree carries the original concrete external-bound pair:
- `qssm_main_theorem_realworld_concrete_256`
- `qssm_main_theorem_realworld_concrete_256_5_over_2_226`

It also carries the fully reduction-facing sibling pair:
- `qssm_main_theorem_realworld_concrete_256_with_all_reductions`
- `qssm_main_theorem_realworld_concrete_256_with_all_reductions_5_over_2_226`

Current concrete arithmetic:
- component epsilon = `1 / 2^226`
- top epsilon = `5 / 2^226`
- effective bit level ≈ `223.67807190511263`

Premise status:
- LE rejection, LE FS, MS1, and MS2 each enter through explicit external reduction obligations
- those obligations are theorem premises, not axioms
- the abstract real-world and concrete companion routes package externally supplied upper-bound budgets only
- these theorem surfaces do not prove weighted or non-uniform sampler internals

Caveat:
- the frozen toy `3%r / 64%r` lower masses do not instantiate `1 / 2^226`
- no theorem claims the toy actuals are `<= 2^-226`

## Compression Interpretation

Within the programmable ROM framing used by the theorem:
- `A1` and `A2` can be discussed under ROM umbrella language
- `A4` combines ROM-programmed FS behavior plus concrete LE parameter conditions

For audit clarity, the proof artifact keeps `A1`, `A2`, and `A4` separate.

## Dominance / Security Floor

Practical floor remains controlled by LE FS entropy and Set B constraints:
- LE FS floor: about `132.2` bits
- Soundness floor target in docs/checklists: `121` bits

MS hash-binding and MS-ROM terms stay lower-order under normal query budgets.

## Formal Coverage Boundary

- LE constants, challenge-expansion details, prover attempt bounds, and numeric floors mentioned here are spec/security-analysis facts and executable validation targets, not current EasyCrypt embedded constants.
- EasyCrypt currently proves symbolic and predicate-level consequences over named budget owners and LE predicates.
- Concrete constant conformance would require Rust tests and audits, or a separate EasyCrypt refinement/model layer.
- Soundness floor references in this file are security-analysis scope and are not current EasyCrypt theorem outputs.

## Parameter-Condition Obligations

Set B verification relies on executable numeric checks, including:
- `gamma == eta + ||cr||_inf` style relationship checks in proof crate tests
- independent LE Set B recomputation and external fixture validation
- fixed schema version and explicit float tolerance (`2^-64`) for external validation artifacts

## What Is and Is Not Claimed

- This analysis describes the current code-backed theorem surface.
- It does not claim a standard-model replacement for programmed Fiat-Shamir steps.
- It does not collapse simulator exactness lemmas (`MS-3a/3b/3c`) into new assumptions.

## Source Mapping

- theorem object and assumption table:
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_core.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_graph.rs`
- LE external validation artifacts/tests:
  - `truth-engine/qssm-proofs/src/lattice/external_validation.rs`
  - `truth-engine/qssm-proofs/tests/external_le_validation.rs`
  - `truth-engine/qssm-proofs/tests/parameter_sync.rs`
