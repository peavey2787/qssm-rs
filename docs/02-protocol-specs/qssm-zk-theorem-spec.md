# QSSM Zero-Knowledge Theorem Specification

## Status

This document freezes the current publishable theorem artifact for the canonical composed design:

- MS v2 Option B
- LE Set B
- game-based proof chain `G0 -> G1 -> G2`
- global simulator `simulate_qssm_transcript`

The source of truth for the executable theorem object is `truth-engine/qssm-proofs/src/reduction_zk.rs`.

## Scope

This specification records:

- the exact simulation-based zero-knowledge claim carried by the proof crate
- the explicit games `G0`, `G1`, and `G2`
- the public-input-only global simulator
- the assumption-to-epsilon mapping for `A1`, `A2`, and `A4`
- a witness-independence audit of the simulator call chain
- safe external claim language

This document does not upgrade any assumption beyond what the code currently states. In particular, it does not silently convert custom proof obligations into standard hardness assumptions.

The MS simulation layer is discharged by explicit exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c`, which contribute zero residual advantage by construction. The theorem depends only on `A1` (hash binding), `A2` (ROM programmability), and `A4` (LE HVZK bound).

## Security Model

The theorem is stated in the programmable Random Oracle Model over the frozen QSSM verifier view.

The frozen boundary assumptions are:

- the MS v2 transcript and API are fixed
- the LE Set B parameter surface is fixed
- the simulator interfaces and shared-randomness rules are fixed
- the theorem object is invalidated by future structural rewrites until closure is rerun

## Exact Theorem Statement

For every PPT distinguisher `D` over the full joint transcript, let:

- `G0` be the real QSSM transcript game
- `G1` be the hybrid game where only the MS component is replaced by its simulator
- `G2` be the ideal game produced by the public-input-only global simulator `S = simulate_qssm_transcript`

Then:

```text
|Pr[D(G0)=1] - Pr[D(G2)=1]| <= epsilon_ms_hash_binding
                               + epsilon_ms_rom_programmability
                               + epsilon_le
```

Equivalently:

```text
Adv_QSSM(D) <= epsilon_qssm
epsilon_qssm = epsilon_ms_hash_binding
             + epsilon_ms_rom_programmability
             + epsilon_le
```

The MS simulation layer (formerly carried as a separate assumption) now contributes exactly zero advantage by the exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c`.

## Global Simulator

The global simulator is:

```text
simulate_qssm_transcript(public_input, simulator_seed)
```

Its public input interface is:

- `MsHiddenValuePublicInput`
- `LePublicInput`
- one ambient simulator seed

Its forbidden inputs are:

- MS hidden value
- MS commitment blinders
- MS prover seed
- LE witness `r`
- LE prover seed

### Definition

Given `(public_input, simulator_seed)`:

1. Reconstruct the MS public statement from `public_input.ms` only.
2. Derive `ms_seed` by domain-separated hashing of:
   - the simulator seed
   - the public MS statement digest
3. Derive `le_seed` by domain-separated hashing of:
   - the simulator seed
   - the LE binding context
   - the LE CRS seed
4. Output:
   - `simulate_ms_v2_transcript(public_input.ms, ms_seed)`
   - `simulate_le_transcript(public_input.le, le_seed)`

The shared-randomness rule is:

```text
one ambient simulator seed -> domain-separated MS seed + domain-separated LE seed
```

No witness state is shared across the two component simulators.

## Games

### `G0` Real Game

Distribution:

```text
sample_real_qssm_transcript(ms witness, le witness, public_input)
```

Interpretation:

- MS v2 uses the real prover
- LE uses the real prover
- this is the baseline verifier-view distribution

### `G1` MS-Replaced Hybrid

Distribution:

```text
MS transcript from simulate_ms_v2_transcript
LE transcript from sample_real_le_transcript
```

Interpretation:

- MS is simulated
- LE remains real
- this isolates the MS replacement loss

### `G2` Ideal Simulated Game

Distribution:

```text
simulate_qssm_transcript(public_input, simulator_seed)
```

Interpretation:

- both components are simulated
- the full joint transcript is emitted from public inputs only

## Transition Lemmas

### `G0 -> G1`

Claim:

```text
Adv_G0_G1(D) <= epsilon_ms_hash_binding
             + epsilon_ms_rom_programmability
```

Justification:

- `MS-1`: replace witness-bound commitment handling by a boundary-consistent abstraction (loss: `epsilon_ms_hash_binding`)
- `MS-2`: replace real Fiat-Shamir derivation by programmed oracle answers on the frozen boundary (loss: `epsilon_ms_rom_programmability`)
- `MS-3a`: exact bitness transcript simulation under programmed challenges (zero advantage by construction)
- `MS-3b`: true-clause public-point characterization `P = r * H` at the highest differing bit (zero advantage by construction)
- `MS-3c`: exact comparison-clause simulation under programmed challenges (zero advantage by construction)

Assumptions consumed:

- `A1`
- `A2`

### `G1 -> G2`

Claim:

```text
Adv_G1_G2(D) <= epsilon_le
```

Justification:

- replace the LE prover by `simulate_le_transcript`
- compose the MS and LE simulators through domain-separated shared randomness
- preserve simulator independence and additive composition

Assumptions consumed:

- `A4`

## Assumptions and Epsilon Terms

| Assumption | Epsilon term | Statement in theorem object | Audit classification | Notes |
| --- | --- | --- | --- | --- |
| `A1` | `epsilon_ms_hash_binding` | `ValueCommitmentV2` and the MS statement digest are binding on the frozen observable boundary | Standard-style, scheme-instantiated | This is a conventional binding/collision-resistance style assumption, but it is instantiated through the concrete `ValueCommitmentV2` and digest construction rather than an abstract generic commitment theorem. |
| `A2` | `epsilon_ms_rom_programmability` | the MS Fiat-Shamir oracle is programmable on the frozen observable boundary | Standard model assumption | This is the usual programmable-ROM assumption used by Fiat-Shamir simulation arguments. |
| `A4` | `epsilon_le` | the LE Set B simulator satisfies the encoded rejection-sampling and Fiat-Shamir bound | Standard-style but parameterized and scheme-specific | This is an HVZK-style proof bound for the concrete LE system under current Set B parameters. It is not stated as a standalone SIS/LWE theorem inside this file; it remains a parameterized proof obligation tied to the encoded rejection-sampling template. |

Note: The MS simulation layer is discharged by the exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c`. No separate cryptographic assumption is required for it.

## Epsilon Audit

### `epsilon_ms_hash_binding`

- Source: `A1`
- Theorem role: MS leaf loss in `G0 -> G1`
- Standardness: acceptable as standard-style binding if stated against the concrete MS commitment and statement digest construction
- Open caution: do not restate it as generic commitment binding without naming the concrete MS construction

### `epsilon_ms_rom_programmability`

- Source: `A2`
- Theorem role: MS Fiat-Shamir programming loss in `G0 -> G1`
- Standardness: standard ROM assumption
- Open caution: must remain explicitly ROM-scoped

### `epsilon_le`

- Source: `A4`
- Theorem role: LE replacement loss in `G1 -> G2`
- Encoded components:
  - rejection-sampling term
  - Fiat-Shamir term
- Standardness: standard-style HVZK argument for the concrete LE proof template, but still parameterized and scheme-specific in this codebase
- Open caution: the public statement should mention Set B and the encoded parameter conditions

## Witness-Independence Audit

The required question is whether the global simulator, including its indirect dependencies, ever consumes witness-derived data.

### Direct Interface Check

`simulate_qssm_transcript` takes only:

- `QssmPublicInput`
- `simulator_seed`

It does not accept any witness, prover randomness, hidden value, or commitment opening.

### MS Call Chain Audit

Call chain:

```text
simulate_qssm_transcript
  -> ms_v2_statement_from_public_input
  -> simulate_ms_v2_transcript
  -> qssm_ms::simulate_predicate_only_v2
```

Audit result:

- `ms_v2_statement_from_public_input` reconstructs the MS statement from public commitment points, target, binding entropy, binding context, and context only
- `simulate_ms_v2_transcript` passes only the public statement plus a simulator seed into `qssm_ms::simulate_predicate_only_v2`
- `qssm_ms::simulate_predicate_only_v2` itself accepts only `(&PredicateOnlyStatementV2, simulator_seed)` and derives all announcements, challenges, and responses from the public statement digest and simulator seed

Conclusion:

```text
No witness-derived MS value appears anywhere in the simulator call chain.
```

### LE Call Chain Audit

Call chain:

```text
simulate_qssm_transcript
  -> simulate_le_transcript
  -> sample_centered_vec_with_seed
  -> le_public_binding_fs_bytes
  -> le_mu_from_public
  -> le_fs_programmed_query_digest
```

Audit result:

- `simulate_le_transcript` takes only `LePublicInput` and a simulator seed
- `sample_centered_vec_with_seed` derives vectors from `(label, simulator_seed, binding_context, index)` only
- `le_public_binding_fs_bytes` serializes the public binding only
- `le_mu_from_public` lifts the public binding into `RqPoly`
- challenge programming depends on public binding context, CRS seed, public digest coefficients, and simulated transcript values, not on witness `r`

Conclusion:

```text
No witness-derived LE value appears anywhere in the simulator call chain.
```

### Composition Audit

The composition rule is:

- one ambient simulator seed is split into domain-separated component seeds
- the MS seed is derived from the simulator seed and public MS statement digest
- the LE seed is derived from the simulator seed, LE binding context, and LE CRS seed

Negative finding check:

- no witness bytes are mixed into either seed derivation
- no real prover seed is reused in the simulator path
- the simulator path never calls `sample_real_qssm_transcript`, `sample_real_le_transcript`, or `qssm_ms::prove_predicate_only_v2`

Conclusion:

```text
The global simulator is witness-independent in its current code path.
```

This is a code-structure audit, not a machine-checked noninterference proof.

## Claim Tiers

### Conservative Claim

Safe external statement:

```text
The canonical QSSM design admits a game-based simulation theorem in the programmable Random Oracle Model: under explicit assumptions A1 (hash binding), A2 (ROM programmability), and A4 (LE HVZK bound), every PPT distinguisher between the real joint transcript and the global simulator output has advantage at most epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le. The MS simulation layer contributes zero residual advantage by exact-simulation lemmas MS-3a, MS-3b, and MS-3c.
```

Why this is safe:

- it is exactly what the proof crate states
- every assumption is named and accounted for
- it does not overclaim negligibility

### Standard Claim

Usable when assumptions are stated in full:

```text
QSSM is simulation-based zero-knowledge in the programmable Random Oracle Model for the frozen MS v2 Option B plus LE Set B interface, assuming concrete MS commitment/digest binding, MS Fiat-Shamir programmability, and the encoded LE Set B HVZK bound. The MS predicate-only transcript simulation is exact under programmed challenges.
```

Why this is reasonable:

- it preserves the ROM scope
- it keeps the scheme-specific assumptions explicit
- the MS simulation gap is discharged exactly, not by a named assumption

### Strong Claim

Safe as a conditional statement:

```text
If epsilon_ms_hash_binding, epsilon_ms_rom_programmability, and epsilon_le are all negligible in the security parameter, then the canonical frozen QSSM construction is provably simulation-based zero-knowledge in the programmable Random Oracle Model.
```

Publication note:

- `A4` remains a concrete Set B parameterized proof obligation, not a theorem imported from an external formal development

## Recommended Public Position

The strongest currently safe public sentence is the standard claim.

The strong claim is acceptable in technical material if the assumption table and Set B parameter conditions are included immediately nearby.

## Proof-Assistant-Friendly Skeleton

The following is a non-mechanized export skeleton for Lean or Coq style formalization.

```text
constant G0 : Distribution JointTranscript
constant G1 : Distribution JointTranscript
constant G2 : Distribution JointTranscript

constant simulate_qssm_transcript : QssmPublicInput -> Seed -> JointTranscript

axiom A1_hash_binding :
  forall D, Adv_G0_G1_MS1 D <= epsilon_ms_hash_binding

axiom A2_ms_rom_programmability :
  forall D, Adv_G0_G1_MS2 D <= epsilon_ms_rom_programmability

-- MS-3a/3b/3c: exact simulation lemmas (zero advantage by construction)
lemma MS_3a_exact_bitness_simulation :
  forall D, Adv_MS_3a D = 0

lemma MS_3b_true_clause_correctness :
  forall D, Adv_MS_3b D = 0

lemma MS_3c_exact_comparison_simulation :
  forall D, Adv_MS_3c D = 0

axiom A4_le_hvzk_bound :
  forall D, Adv_G1_G2 D <= epsilon_le

theorem g0_to_g1 :
  forall D,
    |Pr[D(G0)=1] - Pr[D(G1)=1]|
      <= epsilon_ms_hash_binding
       + epsilon_ms_rom_programmability

theorem g1_to_g2 :
  forall D,
    |Pr[D(G1)=1] - Pr[D(G2)=1]| <= epsilon_le

theorem qssm_zk :
  forall D,
    |Pr[D(G0)=1] - Pr[D(G2)=1]|
      <= epsilon_ms_hash_binding
       + epsilon_ms_rom_programmability
       + epsilon_le
```

This skeleton is suitable for externalization, but it is not itself a proof assistant development.