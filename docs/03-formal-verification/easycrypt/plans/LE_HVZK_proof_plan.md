# LE HVZK Proof Plan

## Objective

Refine the LE Set-B HVZK boundary into narrower, named obligations while keeping
`epsilon_le` as the final budget for the `G1 -> G2` hop.

## Current Layering

The LE theory is split across `le/LESurface.ec`, `le/LESetB.ec`, `le/LERejection.ec`,
`le/LEFsProgramming.ec`, `le/LEViewIndist.ec`, `le/LEStatisticalDistance.ec`, and
`le/LEHVZK.ec`, with `le/LEModel.ec` as a facade that imports them in dependency order.
Symbols and proof obligations are unchanged from the former monolithic layout; the
following describes where each layer lives:

**Client imports:** EasyCrypt does not re-export symbols from transitive `require import`
chains. Theories that use LE **operators** (for example `le_game_hop_adv`) should
`require import LESurface` (in addition to `LEModel` if they need the full lemma closure).
`games/GameLEBridge.ec` also `require import LEHVZK` for `A_LE_HVZK_transition_bound`.

- **Surface / Set-B / views (ops + basic preds):** `le/LESurface.ec`
- **Set-B projection lemmas + view-defined-from-sound:** `le/LESetB.ec`
- **Lower rejection sampler surface:** `le/LERejectionSampler.ec`
- **Rejection sampling / surrogate / rejection sdist axiom:** `le/LERejection.ec`
- **FS programming chain + FS surrogate shape + FS sdist axiom:** `le/LEFsProgramming.ec`
- **View indistinguishability + distribution links:** `le/LEViewIndist.ec`
- **Triangle / distinguisher–sdist / advantage from indistinguishability:** `le/LEStatisticalDistance.ec`
- **Top-level HVZK packaging lemmas:** `le/LEHVZK.ec`

The obligations below are organized by topic (same names as in the `.ec` files):

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
  - axiom `A_LE_rejection_surrogate_preserves_shape` (coefficients / digest fields
    fixed by `le_post_rejection_surrogate` on each observable)
  - proved lemmas `L_LE_rejection_output_shape_implies_sampling_bound_ok`,
    `L_LE_rejection_output_shape_implies_sampling_hiding_bound`,
    `A_LE_rejection_surrogate_hides_witness` (currently definitional on
    `le_rejection_witness_hiding_core`), `A_LE_rejection_witness_hiding_statistical_bound`
- LE FS/ROM sub-layer:
  - `A_LE_fs_query_surface_defined`
  - `A_LE_fs_programmable_oracle_available`
  - `A_LE_fs_programming_preserves_transcript_shape`
  - axiom `A_LE_fs_surrogate_preserves_shape` (coefficients / digest fields fixed
    by `le_fs_view_surrogate` on each observable)
  - proved lemma `A_LE_fs_programming_cost_bounded_by_epsilon_le` (pred packaging
    from transcript-shape preservation and `A4_le_hvzk_bound_nonneg`)
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
    (d_le_sim_view x s)` (EasyCrypt `SDist` theory); abstract surrogates
    `le_post_rejection_surrogate`, `le_fs_view_surrogate` on
    `le_transcript_observable`, with `d_le_post_rejection_view x s` **defined** as
    `dmap (d_le_real_view x s) le_post_rejection_surrogate` and `d_le_sim_view x s`
    **defined** as `dmap (d_le_post_rejection_view x s) le_fs_view_surrogate`;
    proved lemmas `A_LE_real_to_post_rejection_distribution_link`,
    `A_LE_post_rejection_to_sim_distribution_link` (definitional packaging); axiom
    `A_LE_rejection_surrogate_sdist_bound` and axiom `A_LE_fs_surrogate_sdist_bound`
    (each leg `<= (1/2) * epsilon_le` in `dmap` form); proved lemmas
    `A_LE_rejection_half_sdist_bound`, `A_LE_fs_half_sdist_bound` (aliases of the
    surrogate sdist axioms); proved lemmas
    `A_LE_rejection_contributes_to_sdist`, `A_LE_fs_contributes_to_sdist`; proved
    `A_LE_combined_hiding_bounds_sdist` (`sdist_triangle` + `ler_add` + real
    arithmetic); abstract event `le_distinguisher_event D` on
    `le_transcript_observable`, with `le_view_distinguish_pr d D = mu d
    (le_distinguisher_event D)`; packaging ops/preds `le_view_distinguishing_adv`,
    `le_view_statistical_distance_bound`; proved `A_LE_view_indist_to_sd_bound`
    (unpacks `le_real_sim_view_indistinguishable` and applies the combined lemma); proved
    `A_LE_distinguisher_event_probability_bounded_by_sdist` (one-sided
    distinguisher gap from `sdist_upper_bound` on that event, plus real order);
    proved wrapper `A_LE_sd_bound_to_adv_bound` (same conclusion; the
    `le_view_statistical_distance_bound` hypothesis is not used for the core
    inequality)
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
   - **Done (skeleton):** `A_LE_view_indist_to_sd_bound` is proved from
     `A_LE_combined_hiding_bounds_sdist`, which uses `sdist_triangle` on
     `d_le_real_view`, `d_le_post_rejection_view`, `d_le_sim_view` and the two
     half-budget lemmas above. Proof debt is instantiating the surrogates and
     discharging `A_LE_rejection_surrogate_sdist_bound`,
     `A_LE_fs_surrogate_sdist_bound`, `A_LE_rejection_surrogate_preserves_shape`, and
     `A_LE_fs_surrogate_preserves_shape` from concrete rejection / FS distribution
     analyses (the post-to-sim **distribution link** is now definitional).
   - **Done (skeleton):** `A_LE_distinguisher_event_probability_bounded_by_sdist`
     packages the standard event bound via `SDist.sdist_upper_bound` on
     `le_distinguisher_event D`; `A_LE_sd_bound_to_adv_bound` is a thin wrapper.
     Further proof debt is giving a concrete / compatible definition of
     `le_distinguisher_event` when the distinguisher is instantiated.
   - Projected hop advantage agrees with `le_view_distinguishing_adv` via proved
     `A_LE_projected_advantage_matches_view_distance`; packaging lemma
     `A_LE_view_advantage_bound_from_indistinguishability` yields
     `le_game_hop_adv x s D <= epsilon_le`.

## Remaining LE Proof Debt

- Remaining LE-HVZK axioms are:
  - `A_LE_rejection_distribution_defined`
  - `A_LE_rejection_acceptance_probability_bounded`
  - `A_LE_rejection_output_shape_preserved`
  - `A_LE_rejection_surrogate_preserves_shape`
  - `A_LE_fs_query_surface_defined`
  - `A_LE_fs_programmable_oracle_available`
  - `A_LE_fs_programming_preserves_transcript_shape`
  - `A_LE_fs_surrogate_preserves_shape`
  - `A_LE_rejection_surrogate_sdist_bound`
  - `A_LE_fs_surrogate_sdist_bound`
- Critical-path audit, May 2026:
  - `LEViewIndist.ec`, `LEStatisticalDistance.ec`, `LEHVZK.ec`, and `games/GameLEBridge.ec` do not add new axioms; they only package lower obligations.
  - The active theorem path is:
    `A_LE_rejection_surrogate_sdist_bound` + `A_LE_fs_surrogate_sdist_bound`
    -> `A_LE_combined_hiding_bounds_sdist`
    -> `A_LE_view_advantage_bound_from_indistinguishability`
    -> `A_LE_real_sim_transcript_equiv_bound`
    -> `A_LE_SetB_HVZK_bound`
    -> `A_LE_HVZK_transition_bound`
    -> `A_G1_to_G2_le_transition_bound`
    -> theorem-level use of `A4_le_hvzk` in `MainTheorem.ec`.
  - The rejection-definition / acceptance / output-shape bundle and the FS query/oracle/shape bundle feed the hiding predicates used by the same chain, via `A_LE_rejection_sampling_hiding_bound` and `A_LE_fs_programming_bound`.
  - `A_LE_rejection_surrogate_preserves_shape` and `A_LE_fs_surrogate_preserves_shape` remain declared debt, but they are currently not referenced by that active chain.
  - Recommended first target: `A_LE_rejection_surrogate_sdist_bound`. It is the earliest quantitative theorem on the critical path, it anchors the concrete meaning of `d_le_post_rejection_view`, and proving it is the most likely way to collapse several rejection-side helper axioms together rather than only removing a packaging leaf.
  - Probe result, May 2026: a direct proof attempt for `A_LE_rejection_surrogate_sdist_bound` does not close from the current surface. After unfolding `le_rejection_sampling_hiding_bound`, the rejection hypotheses collapse to the same budget fact `0%r <= epsilon_le`, while `le_rejection_distribution_defined`, `le_rejection_acceptance_probability_bounded`, and `le_rejection_output_shape_preserved` remain purely predicate packaging with no quantitative link to `sdist`. The exact missing theorem is therefore a sampler theorem below the current rejection facade, not another packaging lemma. A suitable target is a distinguisher-independent statement of the form
    `forall (x : qssm_public_input) (s : seed),`
    `  le_real_view_distribution_defined x s =>`
    `  le_rejection_distribution_defined x s =>`
    `  le_rejection_acceptance_probability_bounded x s =>`
    `  le_rejection_output_shape_preserved x s =>`
    `  sdist (d_le_real_view x s) (d_le_post_rejection_view x s) <= (1%r / 2%r) * epsilon_le.`
    Any honest discharge of `A_LE_rejection_surrogate_sdist_bound` needs this kind of rejection-sampler coupling / distance theorem, or an equivalent lower theorem from which it is derivable.
  - Design refinement, May 2026: name that lower theorem surface explicitly as
    `A_LE_rejection_sampler_sdist_bound` in `le/LERejection.ec`. It should stay
    a lower-layer theorem target, not a replacement quantitative axiom. At the
    current abstraction boundary it is still blocked because `d_le_real_view`
    is abstract in `LESurface.ec`, while `d_le_post_rejection_view` is only the
    definitional `dmap` push-forward through abstract `le_post_rejection_surrogate`.
    The next honest implementation patch must therefore introduce a concrete LE
    rejection execution / sampler surface below those operators, or prove an
    equivalent coupling theorem from such a surface.
  - Minimal sampler skeleton, May 2026: `le/LERejectionSampler.ec` now adds the
    lower ops `d_le_rejection_real_execution_view`, `le_rejection_transform`, and
    `d_le_rejection_post_execution_view`, together with comment-only bridge targets
    `le_real_view_matches_rejection_execution`,
    `le_post_rejection_view_matches_execution_transform`, and
    `A_LE_rejection_sampler_sdist_bound`. This keeps the import direction clean:
    the lower sampler file depends on `LESurface.ec`, but `LERejection.ec` and
    `LEModel.ec` do not import it yet.
- `games/GameLEBridge.ec` no longer carries a game-layer projection axiom:
  `A_game_pr_LE_projection_semantics` is now a lemma on the split views
  `G1_le_real_projection` / `G2_full_sim`.
- The former cross-layer debt between `G_MS_sim` and `G1_le_real_projection`
  is now closed outside the LE-HVZK lane: `sim/Simulator.ec` provides
  `A_extract_ms_public_real_view_probability_eq`, `games/GameAdvantage.ec`
  proves `A_G1_MS_to_LE_transition_bound`, and `theorem/MainTheorem.ec`
  no longer assumes the middle hop separately. The remaining work in this plan
  is therefore only the LE-side rejection / FS / view axioms.

## Exit Criteria

- Replace one or more LE-HVZK axioms with proved lemmas from narrower concrete
  assumptions without changing theorem-facing statements.
- Preserve `A_LE_HVZK_transition_bound` and keep checker passing.
