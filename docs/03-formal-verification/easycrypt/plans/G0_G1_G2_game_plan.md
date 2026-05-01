# G0 -> G1 -> G2 Game-Hop Plan

## Objective

Replace vacuous game skeletons with explicit advantage-bound obligations so the
final QSSM theorem is composed from concrete hops:

- `G0_real_qssm` -> `G1_ms_sim_le_real` (MS transition)
- `G1_ms_sim_le_real` -> `G2_full_sim` (LE transition)
- `G0_real_qssm` -> `G2_full_sim` (composed QSSM bound)

## MS game views (instantiated)

`primitives/QssmTypes.ec` fixes **`game_view`** as a sum type: MS hops use **`GV_ms`** carrying **`ms_game_view_record`** (`msgv_qssm_pub`, `msgv_seed`, `msgv_ms_pub`, `msgv_ms_obs`, **`msgv_stage`** : `ms_game_stage`, `msgv_le_placeholder`). The G2 endpoint uses **`GV_g2_full_sim`** with **`qssm_g2_shell_record`** until LE wiring refines that branch.

In the split game layer (`games/GameTypes.ec`, `games/GameViews.ec`, `games/GameMSHopTypes.ec`, `games/GameMSHopTransitions.ec`, `games/GameMSHopComposition.ec`, re-exported by `games/GameMSHops.ec`), **`G_MS_real`** … **`G_MS_sim`** are **`mk_ms_game_view`** at the matching stage; **`G_MS_real` = `G0_real_qssm`** and **`G_MS_sim` = `G1_ms_sim_le_real`**. Predicate aliases **`ms_game_real_stage`**, **`ms_game_after_binding_stage`**, … **`ms_game_sim_stage`**, plus **`ms_game_view_ms_pub`** and **`ms_game_view_qssm_seed`**, appear as explicit premises on **`A_MS1_*`** … **`A_MS3c_*`**. Canonical pairs **`(G_MS_* x xms s)`** satisfy those premises via proved lemmas **`L_ms_MS1_stage_premises`** … **`L_ms_MS3c_stage_premises`**, which the composed MS hop proof uses when applying the segment axioms.

## Current non-vacuous obligations

From the split game layer (`games/GameAdvantage.ec`, `games/GameMSHops.ec`, `games/GameLEBridge.ec`, re-exported by `games/Games.ec`):

- `A_adv_gamehop_triangle` (**lemma**, derived from `Adv_def` + real arithmetic)
- `A_G0_to_G1_ms_transition_bound` (**lemma**, telescope `A_adv_ms_hop_telescope` + segment axioms `A_MS1_*` … `A_MS3c_*`)
- `A_G1_to_G2_le_transition_bound` (**lemma**, from `A_LE_HVZK_transition_bound` + game/LE adv bridge)

From `theorem/MainTheorem.ec`:

- `qssm_main_theorem_skeleton` (**lemma**) derives
  `Adv_G0_G2_QSSM <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le`
  from the two hop bounds plus triangle composition.

## Dependency wiring targets

### G0 -> G1 (MS side)

`A_G0_to_G1_ms_transition_bound` is a **proved lemma** composing:

- Intermediate views: `G_MS_real` (= `G0_real_qssm x xms s`), `G_MS_after_binding`, `G_MS_after_rom`, `G_MS_after_bitness`, `G_MS_after_comparison`, `G_MS_sim` (= `G1_ms_sim_le_real x xms s`), all **`GV_ms`** with the same `(x, xms, s)` and aligned `msgv_stage`.
- Telescope: `A_adv_ms_hop_telescope` (sum of five segment advantages).
- Segment game-layer obligations (proof debt; MS1 is split into a **narrow axiom** plus a **lemma**):
  - **MS1 (hash binding):** canonical bound `A_MS1_canonical_hash_binding_bound` is now a **lemma** (same conclusion) layered over three narrower obligations: `A_MS1_hash_binding_surface_defined`, `A_MS1_hash_binding_bad_event_bounded`, and `A_MS1_hash_binding_replacement_advantage_bound`. **`A_MS1_hash_binding_transition`** remains a **proved lemma** applying this canonical bound directly. Generic wrapper axiom `A_MS1_hash_binding_replacement_bound` is removed. Canonical step witness remains available via `L_ms1_hash_binding_step_canonical`. Cryptographic discharge (e.g. Blake3) stays out of this skeleton; budget ties to `ms/MS.ec` (`epsilon_ms_hash_binding`, `A1_ms_hash_binding_nonneg`) and theorem `A1_ms_hash_binding`.
  - **MS2 (ROM / FS programmability):** canonical bound `A_MS2_canonical_rom_programming_bound` is now a **lemma** (same conclusion) layered over three narrower ROM obligations: `A_MS2_rom_query_surface_defined`, `A_MS2_rom_programmed_points_bounded`, and `A_MS2_rom_reprogramming_advantage_bound`. **`A_MS2_rom_programming_transition`** remains a **proved lemma** applying this canonical bound directly. Generic wrapper axiom `A_MS2_rom_programming_replacement_bound` is removed. Canonical step witness remains available via `L_ms2_rom_programming_step_canonical`. Budget and FS interface: `primitives/FS.ec` (`epsilon_ms_rom_programmability`, `A2_ms_rom_programmability_nonneg`, `A2_programmable_oracle_exists`); theorem `A2_ms_rom_programmability`.
  - **MS3a (bitness exact simulation):** primary obligation is canonical axiom `A_MS3a_canonical_bitness_exact_bound` (**axiom**) on `Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r` under `ms3a_bitness_real_sim_equiv xms s`; **`A_MS3a_bitness_transition`** is a **proved lemma** that applies this canonical bound directly. Generic wrapper axiom `A_MS3a_bitness_exact_step_bound` is removed. Canonical step witness remains available via `L_ms3a_bitness_exact_step_canonical`. Source proof debt stays in **`ms/source/`** (`MS_3a_exact_bitness_simulation` / `SourceTheorem`).
  - **MS3b (true clause):** primary obligation is canonical axiom `A_MS3b_canonical_true_clause_bound` (**axiom**) on `Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D <= 0%r` under the existing MS-3b forall bundle; **`A_MS3b_true_clause_transition`** is a **proved lemma** that applies this canonical bound directly. Generic wrapper axiom `A_MS3b_true_clause_exact_step_bound` is removed. Canonical step witness remains available via `L_ms3b_true_clause_exact_step_canonical`. Proof debt in **`ms/TrueClause.ec`** (`MS_3b_true_clause_characterization` and hooks).
  - **MS3c (comparison exact simulation):** primary obligation is canonical axiom `A_MS3c_canonical_comparison_exact_bound` (**axiom**) on `Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D <= 0%r` under the existing MS-3c implication bundle; **`A_MS3c_comparison_transition`** is a **proved lemma** that applies this canonical bound directly. Generic wrapper axiom `A_MS3c_comparison_exact_step_bound` is removed. Canonical step witness remains available via `L_ms3c_comparison_exact_step_canonical`. Proof debt in **`ms/Comparison.ec`** (`MS_3c_exact_comparison_simulation` and payload/scheduling obligations).

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
   `A_Adv_G1_G2_LE_unfolds_to_projected_views` (from narrower probability
   interface axiom `A_game_pr_LE_projection_semantics` (exact non-crypto boundary:
   generic `game_pr` agrees with LE projected probability for `G1`/`G2`), where
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
5. `A_LE_HVZK_transition_bound` is now a **lemma** in `LEModel.ec`, layered over:
   `le_set_b_params_ok`, `le_rejection_sampling_bound_ok`,
   `le_fs_programming_bound_ok`, `le_hvzk_bound`, and an LE-HVZK layering surface
   (Set-B unpackaging and bridge lemmas are **proved**; remaining proof debt is
   the named rejection/FS/view axioms listed in `plans/LE_HVZK_proof_plan.md`).
   `A_LE_SetB_HVZK_bound` is now a **lemma** derived from that layering.

Next: discharge the remaining LE-HVZK axioms (rejection-sampling chain,
FS/ROM chain, view indistinguishability / advantage bound) from a concrete LE
HVZK game skeleton, then revisit replacing
`A_game_pr_LE_projection_semantics` once `game_pr` is given concrete semantics.
Until then, keep it as the single non-crypto LE bridge/interface axiom.

## Proof order

1. ~~Define/lock concrete `game_view` encodings~~ — MS branch done in `QssmTypes` + `Games`; G2 shell remains minimal; refine `GV_g2_full_sim` when LE transcript is threaded.
2. Keep `A_adv_gamehop_triangle` as a proved game-hop arithmetic lemma.
3. ~~Replace `A_G0_to_G1_ms_transition_bound`~~ done; discharge each `A_MS1_*` … `A_MS3c_*` from concrete games + MS proofs.
4. ~~Replace `A_G1_to_G2_le_transition_bound`~~ done; replace `A_LE_HVZK_transition_bound` with a proved LE HVZK statement and the game/LE adv bridge.
5. Keep `qssm_main_theorem_skeleton` as a proved composition lemma (no theorem-level axiom).

## Exit criteria

- No game-hop theorem concluding `true`.
- `A_adv_gamehop_triangle` proved as a game-hop arithmetic lemma.
- Transition bounds stated and proved as real inequalities on named advantages.
- Main theorem remains an additive game-hop inequality with explicit dependencies.
