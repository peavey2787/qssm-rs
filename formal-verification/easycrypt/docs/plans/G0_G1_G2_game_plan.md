# G0 -> G1 -> G2 Game-Hop Plan

Navigation: [EasyCrypt README](../../README.md)

## Objective

Replace vacuous game skeletons with explicit advantage-bound obligations so the
final QSSM theorem is composed from concrete hops:

- `G0_real_qssm` -> `G_MS_sim` (closed MS transition)
- `G_MS_sim` -> `G1_le_real_projection` (explicit cross-layer intermediate hop)
- `G1_le_real_projection` -> `G2_full_sim` (LE transition)
- `G0_real_qssm` -> `G2_full_sim` (composed QSSM bound)

## MS game views (instantiated)

`primitives/QssmTypes.ec` fixes **`game_view`** as a sum type: MS hops use **`GV_ms`** carrying **`ms_game_view_record`** (`msgv_qssm_pub`, `msgv_seed`, `msgv_ms_pub`, `msgv_ms_obs`, **`msgv_stage`** : `ms_game_stage`, `msgv_le_placeholder`); the explicit LE-facing G1 hop now uses **`GV_g1_le_real`** with **`qssm_g1_le_real_record`**; the G2 endpoint uses **`GV_g2_full_sim`** with **`qssm_g2_shell_record`**.

In the split game layer (`games/GameTypes.ec`, `games/GameViews.ec`, `games/GameMSHopTypes.ec`, `games/GameMSHopTransitions.ec`, `games/GameMSHopComposition.ec`, re-exported by `games/GameMSHops.ec`), **`G_MS_real`** … **`G_MS_sim`** are **`mk_ms_game_view`** at the matching stage; **`G_MS_real` = `G0_real_qssm`** and **`G_MS_sim`** remains the pure MS simulated endpoint. **`G1_le_real_projection`** is now a distinct LE-facing top-level view and no longer aliases **`G_MS_sim`**. Predicate aliases **`ms_game_real_stage`**, **`ms_game_after_binding_stage`**, … **`ms_game_sim_stage`**, plus **`ms_game_view_ms_pub`** and **`ms_game_view_qssm_seed`**, appear as explicit premises on **`A_MS1_*`** … **`A_MS3c_*`**. Canonical pairs **`(G_MS_* x xms s)`** satisfy those premises via proved lemmas **`L_ms_MS1_stage_premises`** … **`L_ms_MS3c_stage_premises`**, which the composed MS hop proof uses when applying the segment axioms.

## Current non-vacuous obligations

From the split game layer (`games/GameAdvantage.ec`, `games/GameMSHops.ec`, `games/GameLEBridge.ec`, re-exported by `games/Games.ec`):

- `A_adv_gamehop_triangle` (**lemma**, derived from `Adv_def` + real arithmetic on the explicit three-hop chain)
- `A_G0_to_G1_ms_transition_bound` (**lemma**, telescope `A_adv_ms_hop_telescope` + segment axioms `A_MS1_*` … `A_MS3c_*`)
- `A_G1_to_G2_le_transition_bound` (**lemma**, from `A_LE_HVZK_transition_bound` + game/LE adv bridge)

From `theorem/MainTheorem.ec`:

- `qssm_main_theorem_skeleton` (**lemma**) derives
  `Adv_G0_G2_QSSM <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le`
  from the closed MS bound, the closed simulator extraction bridge, and the LE bound,
  with `theorem/MainTheorem.ec` now specialized to `extract_ms_public x` rather than a
  free unrelated `xms`.
- The former middle-hop blocker is now closed in two steps: `sim/Simulator.ec`
  states `A_extract_ms_public_real_view_probability_eq`, and
  `games/GameAdvantage.ec` proves `A_G1_MS_to_LE_transition_bound` by collapsing
  `G_MS_sim` to the concrete MS real surface and then applying that bridge.

## Dependency wiring targets

### G0 -> G1 (MS side)

`A_G0_to_G1_ms_transition_bound` is a **proved lemma** composing:

- Intermediate views: `G_MS_real` (= `G0_real_qssm x xms s`), `G_MS_after_binding`, `G_MS_after_rom`, `G_MS_after_bitness`, `G_MS_after_comparison`, `G_MS_sim`, all **`GV_ms`** with the same `(x, xms, s)` and aligned `msgv_stage`.
- Telescope: `A_adv_ms_hop_telescope` (sum of five segment advantages).
- Segment game-layer obligations:
  - **MS1 (hash binding):** canonical bound `A_MS1_canonical_hash_binding_bound` is now a **proved lemma** derived from `A_MS1_hash_binding_step_advantage_bound`, which is itself a **proved lemma** from `A_MS1_hash_binding_concrete_pair_advantage_bound`; that concrete pair theorem is now also a **proved lemma**, obtained by unfolding `Adv` / `game_pr` and applying the lower bridge lemma `A_MS1_hash_binding_game_pr_core_bound` in `GameAdvantage.ec`. **`A_MS1_hash_binding_transition`** remains a **proved lemma** applying the canonical bound directly. Canonical step witness remains available via `L_ms1_hash_binding_step_canonical`. The lower `game_pr_ms_core` bridge is now closed on the concrete MS probability surface.
  - **MS2 (ROM / FS programmability):** canonical bound `A_MS2_canonical_rom_programming_bound` is now a **proved lemma** derived from `A_MS2_rom_programming_step_advantage_bound`, which is itself a **proved lemma** from `A_MS2_rom_programming_concrete_pair_advantage_bound`; that concrete pair theorem is now also a **proved lemma**, obtained by unfolding `Adv` / `game_pr` and applying the lower bridge lemma `A_MS2_rom_programming_game_pr_core_bound` in `GameAdvantage.ec`. **`A_MS2_rom_programming_transition`** remains a **proved lemma** applying the canonical bound directly. Canonical step witness remains available via `L_ms2_rom_programming_step_canonical`. The lower `game_pr_ms_core` bridge is now closed because the AfterRom observable law collapses to the same canonical distribution as AfterBinding on the current seed surface.
  - **MS3a (bitness exact simulation):** canonical bound `A_MS3a_canonical_bitness_exact_bound` is now a **proved lemma** on `Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r` under `ms3a_bitness_real_sim_equiv xms s`, discharged through the concrete `game_view` projection in `GameAdvantage.ec`; **`A_MS3a_bitness_transition`** is a **proved lemma** that applies this canonical bound directly. Generic wrapper axiom `A_MS3a_bitness_exact_step_bound` is removed. Canonical step witness remains available via `L_ms3a_bitness_exact_step_canonical`. Source proof debt stays in **`ms/source/`** (`MS_3a_exact_bitness_simulation` / `SourceTheorem`).
  - **MS3b (true clause):** canonical bound `A_MS3b_canonical_true_clause_bound` is now a **proved lemma** on `Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D <= 0%r`, discharged through the concrete `game_view` projection in `GameAdvantage.ec` plus `MS_3b_true_clause_characterization`; **`A_MS3b_true_clause_transition`** is a **proved lemma** that applies this canonical bound directly. Generic wrapper axiom `A_MS3b_true_clause_exact_step_bound` is removed. Canonical step witness remains available via `L_ms3b_true_clause_exact_step_canonical`. Remaining MS-3b proof debt stays in **`ms/TrueClause.ec`** / **`ms/true_clause/`** (`A_ms3b_operand_hdb_implies_value_gt_target` and transcript/execution hooks), not in the game layer.
  - **MS3c (comparison exact simulation):** **`ms/comparison/`** is **axiom-free**; schedule-level **`ms_comparison_exact_simulation_equiv`** is packaged by **`MS_3c_exact_comparison_simulation`** in **`ms/MS.ec`**. The game-layer bridge **`A_MS3c_comparison_bundle_implies_game_pr_equality`** in **`games/GameMSHopTypes.ec`** is now a **proved lemma** (the MS-3c implication bundle ⇒ equality of abstract **`game_pr`** on **`G_MS_after_comparison`** vs **`G_MS_sim`**). Lemma **`A_MS3c_canonical_comparison_exact_bound`** (same **`Adv … <= 0%r`** conclusion as before) is proved from **`Adv_def`** plus that lemma. **`A_MS3c_comparison_transition`** remains a **proved lemma** applying the canonical bound. Canonical step witness remains via `L_ms3c_comparison_exact_step_canonical`.

### G1 -> G2 (LE side)

`A_G1_to_G2_le_transition_bound` is now a **proved lemma** in `games/GameLEBridge.ec` (re-exported by `games/Games.ec`) from:

1. `set_b_parameter_well_formed`
2. `0%r <= epsilon_le` (via `A4_le_hvzk` at call sites, or `A4_le_hvzk_bound_nonneg` directly)
3. `le_real_sim_transcript_equiv x s`
4. `A_LE_game_bridge_consistency` is now a **lemma**, proved from narrow LE bridge obligations:
   constructor-correctness lemmas `A_G1_LE_view_constructor_correct`,
   `A_G2_LE_view_constructor_correct` (now definitional via
   `le_real_view_from_G1`, `le_sim_view_from_G2`), projection lemmas
   `A_G1_LE_view_projects_to_real`, `A_G2_LE_view_projects_to_sim`, and
   bridge lemma `A_LE_projected_adv_matches_game_adv` (itself derived from
   projected-adv layout lemmas `A_LE_projected_real_adv_layout`,
   `A_LE_projected_sim_adv_layout`, game-side unfold lemmas
  `A_Adv_G1_G2_LE_unfolds_to_projected_views` (from proved projection lemma
  `A_game_pr_LE_projection_semantics`, which is now definitional on the split
  view constructors `G1_le_real_projection` / `G2_full_sim`), where
   `game_pr_le_projected true x s D` is the real LE projection and
   `game_pr_le_projected false x s D` is the sim LE projection; packaged by lemmas
   `A_game_pr_on_G1_uses_LE_real_projection`,
   `A_game_pr_on_G2_uses_LE_sim_projection`,
   `A_game_pr_G1_LE_real_view_correct`,
   `A_game_pr_G2_LE_sim_view_correct` and then
   `A_game_pr_G1_equals_projected_real`,
   `A_game_pr_G2_equals_projected_sim`) and
   `A_le_game_hop_adv_unfolds_to_projected_views`
   (packaged by lemmas `A_LE_real_projected_view_matches_G1`,
   `A_LE_sim_projected_view_matches_G2`))
5. `A_LE_HVZK_transition_bound` is now a **lemma** in `le/LEHVZK.ec` (imported via `LEModel.ec`), layered over:
   `le_set_b_params_ok`, `le_rejection_sampling_bound_ok`,
   `le_fs_programming_bound_ok`, `le_hvzk_bound`, and an LE-HVZK layering surface
   (Set-B unpackaging and bridge lemmas are **proved**; remaining proof debt is
   the named rejection/FS/view axioms listed in `plans/LE_HVZK_proof_plan.md`).
   `A_LE_SetB_HVZK_bound` is now a **lemma** derived from that layering.

Next: discharge the remaining LE-HVZK axioms (rejection-sampling chain,
FS/ROM chain, view indistinguishability / advantage bound) from a concrete LE
HVZK game skeleton. The explicit cross-layer intermediate hop is no longer an
open game/theorem blocker: it is now discharged by the simulator extraction bridge
through `A_extract_ms_public_real_view_probability_eq` and
`A_G1_MS_to_LE_transition_bound`.

## Proof order

1. ~~Define/lock concrete `game_view` encodings~~ — MS branch done in `QssmTypes` + `Games`; G2 shell remains minimal; refine `GV_g2_full_sim` when LE transcript is threaded.
2. Keep `A_adv_gamehop_triangle` as a proved game-hop arithmetic lemma.
3. ~~Replace `A_G0_to_G1_ms_transition_bound`~~ done; discharge each `A_MS1_*` … `A_MS3c_*` from concrete games + MS proofs.
4. ~~Replace `A_G1_to_G2_le_transition_bound`~~ done; the LE projection on `G1_le_real_projection` / `G2_full_sim` is now definitional and `A_game_pr_LE_projection_semantics` is a lemma, not an axiom.
5. Keep `qssm_main_theorem_skeleton` as a proved composition lemma; it now uses `extract_ms_public x` directly and no longer assumes the middle hop separately. The next proof target is the remaining LE-HVZK axiom surface, not another game-view rewrite.

## Exit criteria

- No game-hop theorem concluding `true`.
- `A_adv_gamehop_triangle` proved as a game-hop arithmetic lemma.
- Transition bounds stated and proved as real inequalities on named advantages.
- Main theorem remains an additive game-hop inequality with explicit dependencies.
- No remaining game-layer axiom for LE projection semantics.
