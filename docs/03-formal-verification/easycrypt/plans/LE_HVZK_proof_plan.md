# LE HVZK Proof Plan

## Objective

Refine the LE Set-B HVZK boundary into narrower, named obligations while keeping
`epsilon_le` as the final budget for the `G1 -> G2` hop.

## Current Layering

`le/LEModel.ec` now uses the following layered obligations:

- Set-B parameter soundness (proved from `set_b_parameter_well_formed` / `le_set_b_params_ok`):
  - predicates `le_set_b_ring_dimension_valid`, `le_set_b_challenge_size_valid`,
    `le_set_b_norm_bounds_valid`, `le_set_b_eta_gamma_relation_valid` packaging
    the same inequalities as `set_b_parameter_well_formed`
  - projection lemmas `A_LE_SetB_ring_dimension_valid`, …,
    `A_LE_SetB_eta_gamma_relation_valid`
  - `A_LE_SetB_params_sound` and inverse packaging `L_LE_set_b_params_sound_implies_ok`
- LE rejection-sampling / witness-hiding sub-layer:
  - `A_LE_rejection_distribution_defined`
  - `A_LE_rejection_acceptance_probability_bounded`
  - `A_LE_rejection_output_shape_preserved`
  - `A_LE_rejection_witness_hiding_statistical_bound`
- LE FS/ROM sub-layer:
  - `A_LE_fs_query_surface_defined`
  - `A_LE_fs_programmable_oracle_available`
  - `A_LE_fs_programming_preserves_transcript_shape`
  - `A_LE_fs_programming_cost_bounded_by_epsilon_le`
- LE view/distribution interface:
  - proved lemmas `A_LE_real_view_distribution_defined` /
    `A_LE_sim_view_distribution_defined` (from `L_LE_set_b_params_sound_implies_ok`)
  - predicate `le_real_sim_view_indistinguishable` as the conjunction of
    `le_rejection_sampling_hiding_bound` and `le_fs_programming_hiding_bound`
  - proved packaging `L_LE_combined_hiding_implies_view_indist`,
    `A_LE_real_sim_view_indistinguishable_from_bound_ok` (chains
    `A_LE_rejection_sampling_hiding_bound` and `A_LE_fs_programming_bound`), and
    `A_LE_real_sim_view_indistinguishable` (same conclusion from the two hiding
    bounds; view-def hypotheses are compatibility-only)
  - concrete `op le_view_statistical_distance` as `sdist (d_le_real_view x s)
    (d_le_sim_view x s)` (EasyCrypt `SDist` theory); packaging ops/preds
    `le_view_distinguishing_adv`, `le_view_statistical_distance_bound`
  - axioms `A_LE_view_indist_to_sd_bound`, `A_LE_sd_bound_to_adv_bound`
  - proved lemma `A_LE_projected_advantage_matches_view_distance`
  - proved lemma `A_LE_view_advantage_bound_from_indistinguishability` chaining
    the above into `le_hvzk_bound` / `epsilon_le`

`A_LE_real_sim_transcript_equiv_bound` is now a **lemma** derived from the LE
view/distribution interface above (plus `A4_le_hvzk_bound_nonneg`).
`A_LE_fs_programming_bound` is now a **lemma** derived from the LE FS/ROM
sub-layer above.
`A_LE_rejection_sampling_hiding_bound` is now a **lemma** derived from the
rejection-sampling sub-layer above (plus `A4_le_hvzk_bound_nonneg`).
`A_LE_real_sim_view_indistinguishable` is a **proved lemma** (pure packaging of
the two hiding predicates; no separate axiom).
`A_LE_SetB_params_sound` is a **proved lemma** (no axiom); view distribution
lemmas `A_LE_real_view_distribution_defined` / `A_LE_sim_view_distribution_defined`
are also **proved** from `L_LE_set_b_params_sound_implies_ok`.
Then `A_LE_SetB_HVZK_bound` is derived as a **lemma** (no longer an axiom), and
`A_LE_HVZK_transition_bound` remains the game-facing wrapper lemma.

## Intended Discharge Path

1. **Set-B parameter soundness**
   - Done at the skeleton level: `le_set_b_params_sound` unpacks the same
     inequalities as `set_b_parameter_well_formed` into named groups (ring /
     challenge / norm / eta–gamma). Further proof debt is instantiating abstract
     `C_POLY_SIZE`, `ETA`, … with concrete Rust-side values when those operators
     are given definitions.
2. **Rejection-sampling hiding bound**
   - Define the rejection-sampling distribution interface.
   - Bound acceptance probability; preserve output transcript shape.
   - State witness-hiding / statistical distance under `epsilon_le`.
3. **FS programming bound**
   - Define the LE FS query surface and ROM programmability availability.
   - Preserve transcript shape under programming.
   - Bound programming cost under the `epsilon_le` budget.
4. **View-level indistinguishability to advantage bound**
   - Establish that real/sim LE projected view distributions are well-defined
     (proved from Set-B soundness at the skeleton level).
   - Package rejection + FS hiding into `le_real_sim_view_indistinguishable` via
     proved `A_LE_real_sim_view_indistinguishable` /
     `A_LE_real_sim_view_indistinguishable_from_bound_ok` (crypto still lives in
     the rejection and FS axiom bundles below).
   - Discharge `A_LE_view_indist_to_sd_bound` (view-level indistinguishability
     implies `sdist (d_le_real_view x s) (d_le_sim_view x s) <= epsilon_le`).
   - Discharge `A_LE_sd_bound_to_adv_bound` (abstract `le_view_distinguish_pr`
     gap bounded by the same `sdist`; links distinguisher advantage to
     `le_view_statistical_distance`).
   - Projected hop advantage agrees with `le_view_distinguishing_adv` via proved
     `A_LE_projected_advantage_matches_view_distance`; packaging lemma
     `A_LE_view_advantage_bound_from_indistinguishability` yields
     `le_game_hop_adv x s D <= epsilon_le`.

## Remaining LE Proof Debt

- Remaining LE-HVZK axioms are:
  - `A_LE_rejection_distribution_defined`
  - `A_LE_rejection_acceptance_probability_bounded`
  - `A_LE_rejection_output_shape_preserved`
  - `A_LE_rejection_witness_hiding_statistical_bound`
  - `A_LE_fs_query_surface_defined`
  - `A_LE_fs_programmable_oracle_available`
  - `A_LE_fs_programming_preserves_transcript_shape`
  - `A_LE_fs_programming_cost_bounded_by_epsilon_le`
  - `A_LE_view_indist_to_sd_bound`
  - `A_LE_sd_bound_to_adv_bound`
- `A_game_pr_LE_projection_semantics` in `games/GameLEBridge.ec` remains the
  single non-crypto interface boundary (out of scope for this plan).

## Exit Criteria

- Replace one or more LE-HVZK axioms with proved lemmas from narrower concrete
  assumptions without changing theorem-facing statements.
- Preserve `A_LE_HVZK_transition_bound` and keep checker passing.
