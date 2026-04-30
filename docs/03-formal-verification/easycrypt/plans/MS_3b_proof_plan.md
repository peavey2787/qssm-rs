# MS-3b Proof Plan (EasyCrypt)

This note tracks the **true-clause / highest-differing-bit** characterization (MS v2 comparison). The checker-facing entry point is **`ms/TrueClause.ec`**.

## Goal (informal)

Under MS v2 comparison geometry: if the published operands decode to `value_bits` and `target_bits`, the **highest differing bit** is at index `p`, and the **true** branch is the one where the target bit is `0` and the value bit is `1` at that index (with all more significant bits matching), then the **clause public point** exposed on that branch is a **blinder point** on the Schnorr generator `H`, i.e. of the form `P = r * H` (`sch_pubkey r` in the formalization).

## Formalized predicates (`ms/TrueClause.ec`)

| Name | Role |
|------|------|
| `ms3b_comparison_operand_bits` | Hook: links `ms_public_input` to the comparison bit lists (currently trivial `true`; replace with spec-linked decoding). |
| `ms3b_clause_opening_binds` | Hook: opening / transcript binding for `(clause_pub, r)` at index `p` (currently trivial `true`). |
| `ms_bitlists_wf_for_index` | Same length, `p` in range. |
| `ms_bits_agree_more_significant` | Bits at indices `0..p-1` (MSB-first convention) agree. |
| `ms_highest_differing_bit` | WF + disagree at `p` + agreement above `p`. |
| `ms_true_clause_position` | Highest-differing geometry + `target_bits[p]=false` + `value_bits[p]=true`. |
| `ms_clause_public_point_matches_blinder` | `commitment = sch_pubkey blinder` (Pedersen-style on `H`). |
| `ms_true_clause_points_are_blinder_points` | Implication: true-clause position ⇒ clause point matches blinder for bit `true` and scalar `r`. |

**Convention:** index `0` is the most significant bit; indices `0 .. p-1` are more significant than bit `p`.

## Theorem skeleton

- **`MS_3b_true_clause_characterization_from_highest_diff`**: hypotheses `ms3b_comparison_operand_bits`, `ms_highest_differing_bit`, `ms_true_clause_position`, `ms3b_clause_opening_binds` ⇒ conclusion **`ms_true_clause_points_are_blinder_points`** (not `true`).
- **`MS_3b_true_clause_characterization`**: same statement, proved by applying the `from_highest_diff` lemma (packaging alias for callers).

### Intermediate lemmas (dependency chain)

| Lemma | Consumes (directly) |
|--------|---------------------|
| **`MS_3b_bits_from_public_input`** | **`A_ms3b_bit_decomposition_correct`** |
| **`MS_3b_highest_diff_from_bits`** | **`MS_3b_bits_from_public_input`** (hence the bit axiom) and **`A_ms3b_highest_differing_bit_correct`** |
| **`MS_3b_true_clause_from_highest_diff`** | **`MS_3b_highest_diff_from_bits`** (hence both axioms above) |
| **`MS_3b_clause_point_from_opening`** | **`A_ms3b_pedersen_opening_correct`** (proof also threads `Hop`, decomposition, and `ms_true_clause_position` so the opening step sits in a non-vacuous geometric context) |

**`MS_3b_true_clause_characterization_from_highest_diff`** builds `Hbits` via **`MS_3b_bits_from_public_input`**, records **`MS_3b_highest_diff_from_bits`** and **`MS_3b_true_clause_from_highest_diff`** (so the highest-diff / true-clause chain is in the proof term), keeps the caller’s **`ms_true_clause_position`** hypothesis visible (`have _ := Htcp`), then unfolds the packaging predicate and finishes with **`MS_3b_clause_point_from_opening`**. All **three** narrow axioms therefore appear on paths from this theorem to leaves (`A_ms3b_*`).

### Hooks still abstract (not axioms)

Predicates **`ms3b_comparison_operand_bits`** and **`ms3b_clause_opening_binds`** remain defined as **`true`** placeholders. They are **not** separate axioms: they only mark where execution-linked definitions will plug in. Until then, **`A_ms3b_*`** axioms are vacuously easy to satisfy at those hooks, but the **theorem statement** still carries the real geometric and opening hypotheses callers must discharge.

## Named axioms (narrow placeholders)

| Axiom | Intended obligation |
|--------|---------------------|
| `A_ms3b_bit_decomposition_correct` | Operand lists are well-sized / consistent with decoded integers from `x`. |
| `A_ms3b_highest_differing_bit_correct` | Relates comparison / ordering facts to `ms_highest_differing_bit` and the true-clause bit pattern (when used with transcript facts). |
| `A_ms3b_pedersen_opening_correct` | Opening / binding implies `clause_pub = sch_pubkey r` on the true branch. |

There is **no** blanket axiom of the form “MS-3b holds” as `true`.

## Bridge from `theorem/MainTheorem.ec`

**`use_MS_3b`** is a lemma restating the same implication as **`MS_3b_true_clause_characterization`** (for game / bound layer imports).

## Checklist (toward a full proof)

1. Replace **`ms3b_comparison_operand_bits`** and **`ms3b_clause_opening_binds`** with definitions or lemmas tied to `ms_public_input` and the v2 observable transcript (`ms/TranscriptObservable.ec`, `ms/SourceModel.ec`, `ms/source/`).
2. Prove or refine **`A_ms3b_bit_decomposition_correct`** from numeric / list decoding spec.
3. Prove or refine **`A_ms3b_highest_differing_bit_correct`** from comparison algorithm correctness (MSB-first scan).
4. Prove or refine **`A_ms3b_pedersen_opening_correct`** from Schnorr commitment algebra + branch tagging (`ms/SchnorrBranch.ec`).
5. ~~Extend **`MS_3b_true_clause_characterization_from_highest_diff`**~~ — done via the intermediate lemmas above; next work is to **discharge** the three `A_ms3b_*` axioms from spec/algebra and replace the two hook predicates with real transcript-linked definitions.

## Next milestone after MS-3b surface is stable

**MS-3c** is tracked in **`MS_3c_proof_plan.md`** and formalized in **`ms/Comparison.ec`** (this file is MS-3b only). MS-3c now consumes MS-3b explicitly through the `ms3c_true_clause_uses_ms3b_blinder_point` hook and `MS_3b_true_clause_characterization` in `ms/Comparison.ec`.
