# MS-3b Proof Plan (EasyCrypt)

This note tracks the **true-clause / highest-differing-bit** characterization (MS v2 comparison). The checker-facing entry point is **`ms/TrueClause.ec`** (thin **`require export`** facade); definitions and proofs are split under **`ms/true_clause/TrueClauseTypes.ec`**, **`TrueClauseMSB.ec`**, **`TrueClauseTheorem.ec`** (imports still use theory **`TrueClause`**).

## Proof-debt checkpoint (current)

- **Only remaining MS-3b semantic axiom:** **`A_ms3b_operand_hdb_implies_value_gt_target`** — well-formed operands plus **`ms_highest_differing_bit`** imply **`ms3b_value_gt_target_at`** (`nth` value `true`, target `false` at `p`). This is the **narrow bit-direction leaf**; it is **not** provable from **`ms_highest_differing_bit`** + **`ms3b_comparison_operand_bits`** alone (counterexample: `vb = [false]`, `tb = [true]`, `p = 0`).
- **Proved packaging (not debt):** **`L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt`** — **`ms_highest_differing_bit`** + **`ms3b_value_gt_target_at`** ⇒ **`ms3b_msb_first_strict_gt_at`** (pure list / definition unpack).
- **Proved lemma (not debt):** **`A_ms3b_operand_hdb_implies_msb_first_strict_gt`** — follows from the axiom + **`L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt`** (replaces the former single axiom on **`ms3b_msb_first_strict_gt_at`**).
- **Proved lemma (not debt):** **`A_ms3b_comparison_semantics`** — **`nth witness vb p = true`**, by projection from **`A_ms3b_operand_hdb_implies_value_gt_target`**.
- **Proved lemma (not debt):** **`A_ms3b_highest_differing_bit_correct`** — composes **`A_ms3b_hdb_implies_value_one_target_zero`** (now **`exact`** the value-gt axiom) with **`A_ms3b_hdb_implies_true_clause_position`**.
- **Structural / definitional:** **`ms3b_comparison_operand_bits`**, **`ms3b_clause_opening_binds`**, **`ms3b_value_gt_target_at`**, **`ms3b_msb_first_strict_gt_at`**, and the geometry predicates (`ms_highest_differing_bit`, `ms_true_clause_position`, …).

## Goal (informal)

Under MS v2 comparison geometry: if the published operands decode to `value_bits` and `target_bits`, the **highest differing bit** is at index `p`, and the **true** branch is the one where the target bit is `0` and the value bit is `1` at that index (with all more significant bits matching), then the **clause public point** exposed on that branch is a **blinder point** on the Schnorr generator `H`, i.e. of the form `P = r * H` (`sch_pubkey r` in the formalization).

## Formalized predicates (`ms/true_clause/*.ec`, facade `ms/TrueClause.ec`)

| Name | Role |
|------|------|
| `ms3b_comparison_operand_bits` | **Structural:** `value_bits` and `target_bits` have the same positive length (`bool list` operands). Parameter `x : ms_public_input` is reserved for a future decode-from-transcript link (no projection in this skeleton). |
| `ms3b_clause_opening_binds` | **Structural:** true-branch opening is Schnorr-shaped — `ms_clause_public_point_matches_blinder clause_pub true r` (i.e. `clause_pub = sch_pubkey r`). Indices `vb`/`tb`/`p`/`x` are API-stable for callers; further transcript coupling is future work. |
| `ms_bitlists_wf_for_index` | Same length, `p` in range. |
| `ms_bits_agree_more_significant` | Bits at indices `0..p-1` (MSB-first convention) agree. |
| `ms_highest_differing_bit` | WF + disagree at `p` + agreement above `p`. |
| `ms3b_value_gt_target_at` | **Bit-direction slice at `p`:** `value_bits[p]=true` ∧ `target_bits[p]=false` (no WF / “agree above” in the predicate itself). |
| `ms3b_msb_first_strict_gt_at` | **Explicit MSB-first strict-greater at `p`:** WF + agreement above + `value_bits[p]=true` + `target_bits[p]=false`. Equivalent to **`ms_true_clause_position`** (lemma **`L_ms3b_tcp_iff_msb_first_strict_gt`**). Lemma **`L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt`** adds WF + “agree above” from **`ms_highest_differing_bit`**. |
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
| **`MS_3b_bits_from_public_input`** | **`A_ms3b_bit_decomposition_correct`** (proved lemma; definitional on `ms3b_comparison_operand_bits`) |
| **`MS_3b_highest_diff_from_bits`** | **`MS_3b_bits_from_public_input`** and proved lemma **`A_ms3b_highest_differing_bit_correct`** |
| **`MS_3b_true_clause_from_highest_diff`** | **`MS_3b_highest_diff_from_bits`** (hence bit decomposition + **`A_ms3b_highest_differing_bit_correct`**) |
| **`MS_3b_clause_point_from_opening`** | **`A_ms3b_pedersen_opening_correct`** (proved lemma; definitional on `ms3b_clause_opening_binds`) |

**`MS_3b_true_clause_characterization_from_highest_diff`** builds `Hbits` via **`MS_3b_bits_from_public_input`**, records **`MS_3b_highest_diff_from_bits`** and **`MS_3b_true_clause_from_highest_diff`**, keeps the caller’s **`ms_true_clause_position`** hypothesis visible (`have _ := Htcp`), then unfolds the packaging predicate and finishes with **`MS_3b_clause_point_from_opening`**. The leaf **`A_ms3b_hdb_implies_value_one_target_zero`** is a **proved lemma**, derived from lemma **`A_ms3b_comparison_semantics`** and **`A_ms3b_hdb_directionality`**. **`A_ms3b_highest_differing_bit_correct`**, **`A_ms3b_bit_decomposition_correct`**, and **`A_ms3b_pedersen_opening_correct`** are all **proved lemmas** (same names, kept for stable imports).

### Predicate status (vs old `true` stubs)

The former **`true`** hooks are **removed**. `ms3b_comparison_operand_bits` and `ms3b_clause_opening_binds` are now **non-vacuous structural** predicates. Callers must still discharge them with real operands / openings from games or transcripts; the `x` parameter is not yet tied to observables.

## Named obligations (`A_ms3b_*` / related)

**Module split:** structural predicates and HDB projection lemmas live in **`TrueClauseTypes`**; **`ms3b_value_gt_target_at`**, **`ms3b_msb_first_strict_gt_at`**, **`L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt`**, **`L_ms3b_msb_first_strict_gt_at_implies_hdb`**, **`L_ms3b_tcp_iff_msb_first_strict_gt`** in **`TrueClauseMSB`**; axiom **`A_ms3b_operand_hdb_implies_value_gt_target`**, lemmas **`A_ms3b_operand_hdb_implies_msb_first_strict_gt`**, **`A_ms3b_comparison_semantics`**, and the **`MS_3b_*`** characterization chain in **`TrueClauseTheorem`**. All are re-exported by theory **`TrueClause`** (`ms/TrueClause.ec`).

| Name | Status | Role |
|------|--------|------|
| `A_ms3b_bit_decomposition_correct` | **Proved lemma** | Projects `ms3b_comparison_operand_bits` to `size vb = size tb` and `0 < size vb`. |
| `A_ms3b_hdb_implies_bits_above_equal` | **Proved lemma** | From `ms_highest_differing_bit`, extract `ms_bits_agree_more_significant` (third conjunct; conjunction is right-associative in the tactic split). |
| `A_ms3b_hdb_implies_bitlists_wf` | **Proved lemma** | From `ms_highest_differing_bit`, extract `ms_bitlists_wf_for_index`. |
| `A_ms3b_hdb_directionality` | **Proved lemma** | From `ms_highest_differing_bit`, extract disagreement at index `p` (`nth vb p <> nth tb p`). |
| `L_ms3b_msb_first_strict_gt_at_implies_hdb` | **Proved lemma** | Strict-greater pattern ⇒ **`ms_highest_differing_bit`**. |
| `L_ms3b_tcp_iff_msb_first_strict_gt` | **Proved lemma** | **`ms_true_clause_position`** ⇔ **`ms3b_msb_first_strict_gt_at`**. |
| `L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt` | **Proved lemma** | **`ms_highest_differing_bit`** + **`ms3b_value_gt_target_at`** ⇒ **`ms3b_msb_first_strict_gt_at`**. |
| `A_ms3b_operand_hdb_implies_value_gt_target` | **Axiom** | Operands + **`ms_highest_differing_bit`** ⇒ **`ms3b_value_gt_target_at`** (semantic bit-direction leaf). |
| `A_ms3b_operand_hdb_implies_msb_first_strict_gt` | **Proved lemma** | Composes axiom **`A_ms3b_operand_hdb_implies_value_gt_target`** + **`L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt`**. |
| `A_ms3b_comparison_semantics` | **Proved lemma** | Under operands + HDB, **`nth witness vb p = true`** (projection from **`A_ms3b_operand_hdb_implies_value_gt_target`**). |
| `A_ms3b_hdb_implies_value_one_target_zero` | **Proved lemma** | **`exact`** the value-gt axiom under operands + HDB (definitionally the two `nth` facts). |
| `A_ms3b_hdb_implies_true_clause_position` | **Proved lemma** | From `ms_highest_differing_bit` plus those two `nth` facts, prove `ms_true_clause_position` by definition. |
| `A_ms3b_highest_differing_bit_correct` | **Proved lemma** | Composes **`A_ms3b_hdb_implies_value_one_target_zero`** with **`A_ms3b_hdb_implies_true_clause_position`** (same statement as the former single axiom). |
| `A_ms3b_pedersen_opening_correct` | **Proved lemma** | Projects `ms3b_clause_opening_binds` to `ms_clause_public_point_matches_blinder clause_pub true r`. |

There is **no** blanket obligation of the form “MS-3b holds” as `true`.

## Bridge from `theorem/MainTheorem.ec`

**`use_MS_3b`** is a lemma restating the same implication as **`MS_3b_true_clause_characterization`** (for game / bound layer imports).

## Checklist (toward a full proof)

1. ~~Replace vacuous **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`**~~ — done with structural list-length and blinder-point predicates (`ms/true_clause/TrueClauseTypes.ec`, re-exported by `ms/TrueClause.ec`).
2. ~~Prove **`A_ms3b_bit_decomposition_correct`** / **`A_ms3b_pedersen_opening_correct`** as lemmas from those predicates~~ — done (names unchanged for imports).
3. ~~Split / tighten the former **`A_ms3b_highest_differing_bit_correct`** axiom~~ — done; **`A_ms3b_hdb_implies_value_one_target_zero`** is a lemma. ~~**`A_ms3b_comparison_semantics`**~~ is a **proved lemma**; **`A_ms3b_operand_hdb_implies_msb_first_strict_gt`** is now **proved**; remaining semantic hook is **`A_ms3b_operand_hdb_implies_value_gt_target`**.
4. **Enrich** `ms3b_comparison_operand_bits` with a decode from `ms_public_input` / v2 observables (`ms/TranscriptObservable.ec`, `ms/SourceModel.ec`, `ms/source/`) when projections exist, so the strict-greater axiom can be discharged from execution’s comparison semantics.
5. Optionally tighten **`ms3b_clause_opening_binds`** with branch tags / digest preimages from execution spec + `ms/SchnorrBranch.ec` so the opening is not only “point = `sch_pubkey r`” but transcript-consistent.
6. ~~Extend **`MS_3b_true_clause_characterization_from_highest_diff`**~~ — unchanged packaging; proof debt for the true-clause **bit direction** is concentrated in **`A_ms3b_operand_hdb_implies_value_gt_target`**, plus transcript-linked refinements of the two structural predicates.

## Next milestone after MS-3b surface is stable

**MS-3c** is tracked in **`MS_3c_proof_plan.md`** and formalized in **`ms/Comparison.ec`** (this file is MS-3b only). MS-3c now consumes MS-3b explicitly through the `ms3c_true_clause_uses_ms3b_blinder_point` hook and `MS_3b_true_clause_characterization` in `ms/Comparison.ec`.
