# QSSM Zero-Knowledge Theorem Spec

Rust implementation is authoritative. This document is the game-based theorem layer only.

Byte-level execution details are intentionally out of scope here and are specified in:
- `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`

## Frozen Claim

Composed theorem target:
- MS v2 Option B
- LE Set B
- game chain `G0 -> G1 -> G2`

Bound:

```text
Adv_QSSM(D) <= epsilon_ms_hash_binding
             + epsilon_ms_rom_programmability
             + epsilon_le
```

## Route Status

The three-term bound above describes the exact-zero theorem skeleton only.

It is the right statement for the exact-zero public theorem route:
- `qssm_main_theorem`

Current top theorem surfaces also include:
- `qssm_main_theorem_semantic_budget`
- `qssm_main_theorem_parameterized_budget`
- `qssm_main_theorem_realworld_budget`
- `qssm_main_theorem_realworld_concrete_128`
- `qssm_main_theorem_realworld_concrete_128_with_all_reductions`

Live-route caveat:
- the parameterized, abstract real-world, and concrete 128 routes do not get a zero-cost identification from public AfterRom to canonical AfterRom
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- those routes therefore pay a charged public-AfterRom-to-canonical-AfterRom landing and preserve an explicit duplicate MS2 charge

For those charged live routes, the top additive structure is:

```text
epsilon_top = epsilon_MS1
            + epsilon_MS2
            + epsilon_MS2
            + epsilon_LE
```

The duplicated MS2 charge must not be simplified away unless a future theorem proves a zero-cost public-AfterRom to canonical-AfterRom landing.

## Games

`G0`:
- real transcript game (real MS + real LE)

`G1`:
- hybrid game replacing only MS with its simulator while LE remains real

`G2`:
- ideal game where both components are simulator-generated from public input

## Epsilon Decomposition

`G0 -> G1`:
- bounded by `epsilon_ms_hash_binding + epsilon_ms_rom_programmability`

`G1 -> G2`:
- bounded by `epsilon_le`

Total:

```text
|Pr[D(G0)=1] - Pr[D(G2)=1]|
<= epsilon_ms_hash_binding
 + epsilon_ms_rom_programmability
 + epsilon_le
```

## Assumption Mapping

- `A1` -> `epsilon_ms_hash_binding`
  - concrete MS commitment/digest binding loss
- `A2` -> `epsilon_ms_rom_programmability`
  - programmable-ROM loss for MS challenge simulation
- `A4` -> `epsilon_le`
  - LE HVZK simulator replacement loss

## MS Exact-Simulation Lemmas

- `MS-3a`: exact bitness transcript simulation under programmed challenges
- `MS-3b`: true-clause public-point characterization at highest differing bit
- `MS-3c`: exact comparison transcript simulation under programmed challenges

These are modeled as zero-residual exact simulation steps (no additional epsilon term).

## Scope Boundary

This theorem spec does not include:
- transcript field layouts
- byte-level FS pipelines
- hash/XOF packing details
- simulator internal ordering

Those belong exclusively to the concrete execution spec.

## Code Mapping

- theorem core and assumptions:
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_core.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_prob.rs`
- game structure:
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_graph.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/core/theorem_chain.rs`
- lemma objects:
  - `truth-engine/qssm-proofs/src/reduction_zk/transcript/lemmas_a.rs`
  - `truth-engine/qssm-proofs/src/reduction_zk/transcript/lemmas_b.rs`
