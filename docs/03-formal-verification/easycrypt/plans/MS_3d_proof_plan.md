# MS-3d Proof Plan (EasyCrypt)

This note tracks the next MS-side game-layer phase after MS-3c. **MS-3c is now closed at the game boundary**: **`games/GameAdvantage.ec`** projects **`game_pr`** from the concrete **`game_view`** surface, **`games/GameMSHopTypes.ec`** proves the MS-3c AfterComparison/Sim collapse and zero-advantage bound as lemmas, and no MS-3c bridge axiom remains. MS-3d therefore starts from a stable comparison/public-observable boundary and focuses on the remaining MS game-hop assumption debt outside the comparison lane.

**Initialization status:** complete for the MS1/MS2 surface reduction. The six provisional MS1/MS2 axioms in **`games/GameMSHopTypes.ec`** have been collapsed to two canonical stage-pair bound surfaces: **`A_MS1_canonical_hash_binding_bound`** and **`A_MS2_canonical_rom_programming_bound`**.

## Objective

Discharge the remaining MS-side game-layer axioms so the composed MS transition theorem

- **`A_G0_to_G1_ms_transition_bound`** in **`games/GameMSHopComposition.ec`**

depends only on named cryptographic budgets and proved MS-3a / MS-3b / MS-3c statements, not on residual game-layer axioms.

## MS-3c handoff status

- **Stable projection layer:** **`games/GameAdvantage.ec`** now owns **`ms3a_game_pr_stage`**, **`ms3b_game_pr_stage`**, **`ms3c_game_pr_stage`**, **`game_pr`**, **`Adv`**, and **`A_adv_ms_hop_telescope`** as definition/lemma-level game infrastructure. There are no game-layer axioms in this file.
- **Public-observable bridge:** **`L_ms3c_game_view_public_obs_aligns_v2`**, **`L_ms3c_public_obs_seed_alignment`**, and **`L_ms3c_public_obs_payload_alignment`** close the current public game boundary for the native comparison slice and native comparison openings.
- **Closed MS-3c hop:** **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and **`A_MS3c_canonical_comparison_exact_bound`** are proved lemmas in **`games/GameMSHopTypes.ec`**.
- **Comparison-local execution package:** the comparison-side execution-seed package remains below **`ms/SourceModel.ec`**. MS-3d does not need to thread that package into the game layer because the compared public/share surface and public observable are already closed.

## Current game-layer blocker set

| Item | Location | Current status | MS-3d consequence |
|------|----------|----------------|-------------------|
| **`A_MS1_canonical_hash_binding_bound`** | **`games/GameMSHopTypes.ec`** | axiom | Single remaining MS1 game-hop theorem surface on the canonical **`G_MS_real -> G_MS_after_binding`** pair. The old surface-defined / bad-event / replacement placeholders are gone. |
| **`A_MS2_canonical_rom_programming_bound`** | **`games/GameMSHopTypes.ec`** | axiom | Single remaining MS2 game-hop theorem surface on the canonical **`G_MS_after_binding -> G_MS_after_rom`** pair. The old query-surface / programmed-points / reprogramming placeholders are gone. |
| **`game_pr_ms_core`** / **`game_pr_g2_core`** | **`games/GameAdvantage.ec`** | abstract operators, not axioms | Stable interface boundary for now. Not an immediate MS-3d blocker unless this phase aims to give concrete semantics to **`game_pr`** itself. |

## What is already closed on the MS side

- **MS-3a:** **`A_MS3a_canonical_bitness_exact_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3b:** **`A_MS3b_canonical_true_clause_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS-3c:** **`A_MS3c_canonical_comparison_exact_bound`** is a proved lemma in **`games/GameMSHopTypes.ec`**.
- **MS telescope:** **`A_adv_ms_hop_telescope`** is a proved lemma in **`games/GameAdvantage.ec`**.
- **Debt reduction already achieved:** the MS1/MS2 game-layer axiom surface in **`games/GameMSHopTypes.ec`** dropped from six provisional axioms to two canonical stage-pair axioms.
- **Composed MS transition theorem:** **`A_G0_to_G1_ms_transition_bound`** is already a proved lemma in **`games/GameMSHopComposition.ec`**, but its remaining assumption debt still flows through the MS1/MS2 axioms above.

## Relevant dependencies to carry from MS-3c into MS-3d

- **`L_ms3c_game_view_public_obs_aligns_v2`** in **`games/GameAdvantage.ec`**
- **`L_ms3c_public_obs_seed_alignment`** in **`games/GameAdvantage.ec`**
- **`L_ms3c_public_obs_payload_alignment`** in **`games/GameAdvantage.ec`**
- **`A_MS3c_comparison_bundle_implies_game_pr_equality`** in **`games/GameMSHopTypes.ec`**
- **`A_MS3c_canonical_comparison_exact_bound`** in **`games/GameMSHopTypes.ec`**
- **`MS_3c_exact_comparison_simulation`** in **`ms/MS.ec`**

These should be treated as stable handoff facts. MS-3d should not reopen the comparison lane unless the canonical public stage surface itself changes.

## Boundary assessment

The remaining blocker set is **not** in the comparison execution package, nor in the public comparison observable. It is concentrated in the earlier game hops:

- **MS1** now depends on one canonical hash-binding bound surface on the fixed Real/AfterBinding pair.
- **MS2** now depends on one canonical ROM-programming bound surface on the fixed AfterBinding/AfterRom pair.
- **MS3a / MS3b / MS3c** are already exact zero-advantage canonical lemmas on the current **`game_pr`** projection.

This means the correct MS-3d direction is to finalize the game layer by discharging the surviving canonical MS1/MS2 axioms, not by adding new MS-3c structure or by widening the comparison-side execution boundary.

## Recommended proof order

1. **Keep `games/GameAdvantage.ec` fixed** as the stable projection layer unless a concrete semantics for **`game_pr_ms_core`** is explicitly required. The current stage-collapsing design already closes MS-3a / MS-3b / MS-3c.
2. **Discharge `A_MS1_canonical_hash_binding_bound`** in **`games/GameMSHopTypes.ec`** from a concrete hash-binding game statement tied to **`G_MS_real`** and **`G_MS_after_binding`**.
3. **Discharge `A_MS2_canonical_rom_programming_bound`** in **`games/GameMSHopTypes.ec`** from a concrete ROM-programming game statement tied to **`G_MS_after_binding`** and **`G_MS_after_rom`**.
4. **Re-check `A_G0_to_G1_ms_transition_bound`** after MS1/MS2 discharge; the MS3a/MS3b/MS3c segments should remain unchanged zero-advantage lemmas.
5. **Defer non-MS interfaces**: LE bridge assumptions, such as the projected LE probability interface, remain tracked in the LE/game plans and are not the immediate MS-3d blocker set.

## Exit criteria

- No remaining MS-3c game-layer axiom or bridge gap.
- Remaining MS-side game-layer assumption debt reduced to the two canonical cryptographic theorem surfaces for MS1/MS2, or those axioms fully discharged.
- **`A_G0_to_G1_ms_transition_bound`** depends on the MS1/MS2 cryptographic budgets plus proved MS-3a / MS-3b / MS-3c lemmas, with no additional MS-3c-specific game assumptions.
- **`./check_easycrypt.sh`** passes after the planning updates and after each subsequent MS-3d proof step.