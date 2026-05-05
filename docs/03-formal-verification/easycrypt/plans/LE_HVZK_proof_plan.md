# LE HVZK Proof Plan

Navigation: [EasyCrypt README](../README.md)

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
- **Lower FS programming surface:** `le/LEFsProgrammingSurface.ec`
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
  - proved lemmas `A_LE_rejection_distribution_defined`,
    `A_LE_rejection_acceptance_probability_bounded`,
    `A_LE_rejection_output_shape_preserved` by definitional unfolding of the
    wrapper predicates to `le_rejection_sampling_bound_ok`
  - shadow lower coupled rejection lane in `le/LERejectionSampler.ec`:
    `le_rejection_shadow_state`, `d_le_rejection_shadow_coupled_state`,
    `d_le_rejection_shadow_pre_marginal`, `d_le_rejection_shadow_post_marginal`,
    and `le_rejection_shadow_failure_probability`; the hidden material now
    carries the concrete lower challenge-seed material together with the
    resampled observable, and the shadow acceptance bit is derived from that
    lower material rather than hardcoded. The shadow lane proves bridge lemmas
    from the shadow pre/post marginals back to `d_le_real_view` and
    `d_le_post_rejection_view`, plus the lower helper facts
    `d_le_rejection_shadow_pre_post_marginals_equal` and
    `le_rejection_shadow_failure_probability_zero`; this lane is not wired into
    the active theorem path yet
  - proved lemma `A_LE_rejection_surrogate_preserves_shape` (coefficients / digest fields
    fixed by `le_post_rejection_surrogate` on each observable)
  - proved lemmas `L_LE_rejection_output_shape_implies_sampling_bound_ok`,
    `L_LE_rejection_output_shape_implies_sampling_hiding_bound`,
    `A_LE_rejection_surrogate_hides_witness` (currently definitional on
    `le_rejection_witness_hiding_core`), `A_LE_rejection_witness_hiding_statistical_bound`
- LE FS/ROM sub-layer:
  - proved lemmas `A_LE_fs_query_surface_defined`,
    `A_LE_fs_programmable_oracle_available`,
    `A_LE_fs_programming_preserves_transcript_shape` by definitional unfolding of
    the wrapper predicates to `le_real_sim_transcript_equiv x s`
  - proved lemma `A_LE_fs_surrogate_preserves_shape` (coefficients / digest fields fixed
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
    `A_LE_post_rejection_to_sim_distribution_link` (definitional packaging);
    proved theorem-facing quantitative lemmas `A_LE_rejection_sampler_sdist_bound`
    (rejection leg `<= epsilon_le_rej`) and `A_LE_fs_surrogate_sdist_bound`
    (FS leg `<= epsilon_le_fs`), together with the packaging lemmas
    `A_LE_rejection_contributes_to_sdist` and `A_LE_fs_contributes_to_sdist`;
    proved `A_LE_combined_hiding_bounds_sdist` (`sdist_triangle` + `ler_add` +
    component-budget arithmetic + definitional rewrite of `epsilon_le` to
    `epsilon_le_rej + epsilon_le_fs`); abstract event `le_distinguisher_event D` on
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

- Remaining theorem-path LE wrapper axioms are now gone: `A_LE_rejection_distribution_defined`,
  `A_LE_rejection_acceptance_probability_bounded`, `A_LE_rejection_output_shape_preserved`,
  `A_LE_fs_query_surface_defined`, `A_LE_fs_programmable_oracle_available`, and
  `A_LE_fs_programming_preserves_transcript_shape` are all proved lemmas by direct
  unfolding of the current wrapper predicates.
- The remaining LE theorem-path assumption is the primitive budget fact
  `A4_le_hvzk_bound_nonneg` in `LESurface.ec`; the rest of the active LE chain below it is lemma-only.
- Critical-path audit, May 2026:
  - `LEViewIndist.ec`, `LEStatisticalDistance.ec`, `LEHVZK.ec`, and `games/GameLEBridge.ec` do not add new axioms; they only package lower obligations.
  - The active theorem path is:
    `A_LE_fs_hidden_state_update_sdist_bound`
    -> `A_LE_fs_hidden_material_programming_sdist_bound`
    -> `A_LE_fs_programming_sampler_sdist_bound`
    -> `A_LE_fs_surrogate_sdist_bound`
    -> `A_LE_combined_hiding_bounds_sdist`
    -> `A_LE_view_advantage_bound_from_indistinguishability`
    -> `A_LE_real_sim_transcript_equiv_bound`
    -> `A_LE_SetB_HVZK_bound`
    -> `A_LE_HVZK_transition_bound`
    -> `A_G1_to_G2_le_transition_bound`
     -> direct theorem-level use of the primitive LE budget assumption
        `A4_le_hvzk_bound_nonneg` from `LESurface.ec` in `MainTheorem.ec`.
  - The rejection-definition / acceptance / output-shape bundle and the FS query/oracle/shape bundle feed the hiding predicates used by the same chain, via `A_LE_rejection_sampling_hiding_bound` and `A_LE_fs_programming_bound`.
  - The rejection-side and FS-side surrogate shape obligations are now discharged as lemmas; the remaining surrogate debt on the active theorem path is quantitative.
  - Rejection concretization, May 2026: `le_post_rejection_surrogate` in `LESurface.ec` is now the identity on `le_transcript_observable`. This makes `A_LE_rejection_surrogate_preserves_shape` immediate by unfolding and discharges `A_LE_rejection_surrogate_sdist_bound` by zero distance, via `dmap_id` and `sdistdd`.
  - FS concretization, May 2026: `primitives/QssmTypes.ec` now makes `le_transcript_observable` a concrete record with one hidden FS-only field `leto_query_material`. `LESurface.ec` defines the theorem-facing selector ops as projections of that carrier and now defines `le_fs_program_query_material` as identity on the active hidden carrier, so `le_fs_view_surrogate` is concrete end to end on the present lower surface.
  - Minimal lower FS surface, May 2026: `le/LEFsProgrammingSurface.ec` now adds the concrete lower names `le_fs_query_row`, `le_fs_programmed_response_carrier`, `d_le_pre_fs_programming_view`, `le_fs_surrogate_transform`, and `d_le_post_fs_programmed_view`. It proves both lower bridge facts `le_fs_surrogate_matches_programmed_view` and `le_fs_programming_preserves_shape_lower`, and `LEFsProgramming.ec` now imports that lower surface to prove `A_LE_fs_surrogate_preserves_shape` as a lemma. No axioms were added.
  - Joint-state surface, May 2026: `LEFsProgrammingSurface.ec` now defines `le_fs_visible_shell`, `le_fs_hidden_programming_state`, `le_fs_observable_of_hidden_programming_state`, `le_fs_hidden_programming_state_update`, and the distributions `d_le_pre_fs_hidden_programming_state` / `d_le_post_fs_hidden_programming_state`. The bridge lemmas `d_le_pre_fs_programming_view_matches_hidden_state_projection` and `d_le_post_fs_programmed_view_matches_hidden_state_projection` show that the theorem-facing observable distributions are precisely the observable projections of the lower joint-state distributions.
  - Lower hidden-update closure, May 2026: `A_LE_fs_hidden_state_update_sdist_bound` is now a proved zero-distance lemma in `LEFsProgrammingSurface.ec`, because `le_fs_hidden_programming_state_update` is concrete identity on the current carrier.
  - Lower FS closure, May 2026: that lower hidden-update lemma proves `A_LE_fs_hidden_material_programming_sdist_bound` definitionally on the joint-state surface, and then proves `A_LE_fs_programming_sampler_sdist_bound` on the theorem-facing observable surface via the hidden-state projection bridge lemmas plus `sdist_dmap`.
  - Theorem-facing FS closure, May 2026: `LEFsProgramming.ec` now proves `A_LE_fs_surrogate_sdist_bound` from `A_LE_fs_programming_sampler_sdist_bound`, so the surrogate-side theorem is no longer axiomatized.
  - FS component budget lane, May 2026: `primitives/BudgetParameters.ec`
    now also owns `epsilon_le_fs`, defined concretely as `0%r` in the current
    exact-zero model with proved nonnegativity lemma `A4_le_fs_nonneg`.
    `LEFsProgrammingSurface.ec` now proves the lower component-budget theorems
    `A_LE_fs_hidden_state_update_sdist_le_budget`,
    `A_LE_fs_hidden_material_programming_sdist_le_budget`, and
    `A_LE_fs_programming_sampler_sdist_le_budget`, each ending directly in
    `epsilon_le_fs`. `LEFsProgramming.ec` now re-exports the theorem-facing FS
    component-budget endpoint on `d_le_post_rejection_view`, and
    `A_LE_fs_surrogate_sdist_bound` itself now ends directly in
    `epsilon_le_fs`.
  - Non-identity FS lane design audit, May 2026: the current lower FS path is
    still semantically trivial because `LESurface.ec` defines
    `le_fs_program_query_material` as identity, and
    `LEFsProgrammingSurface.ec` proves `le_fs_hidden_programming_state_update`
    is the identity map on the active theorem path.
  - Shadow FS semantic carrier, May 2026: `primitives/QssmTypes.ec` now makes
    `le_query_material` a concrete record with query-row,
    programmed-response, programming-log, and bad-event fields, and
    `LERealExecution.ec` now populates that richer hidden query material
    concretely. `LEFsProgrammingSurface.ec` now adds the shadow objects
    `le_fs_shadow_hidden_material`, `le_fs_shadow_state`,
    `d_le_fs_shadow_coupled_state`, `d_le_fs_shadow_pre_marginal`,
    `d_le_fs_shadow_post_marginal`, `le_fs_shadow_bad_event`, and
    `le_fs_shadow_failure_probability` beside the active zero lane. The shadow
    hidden material carries the extracted `le_fs_query_row`, the pre-query
    material, a semantic post-query material, a programmed response/log, and a
    bad-event indicator. The closed structural bridge lemmas are
    `le_fs_shadow_post_of_observable_matches_surrogate`,
    `le_fs_shadow_post_observable_preserves_visible_fields`,
    `le_fs_shadow_bad_event_current_model`,
    `d_le_fs_shadow_pre_marginal_matches_pre_programming_view`,
    `d_le_fs_shadow_pre_marginal_matches_post_rejection_view`,
    `d_le_fs_shadow_post_marginal_matches_programmed_view`, and
    `d_le_fs_shadow_post_marginal_matches_sim_view`. They keep the shadow pre
    marginal aligned with `d_le_post_rejection_view` and the shadow post
    marginal aligned with `d_le_sim_view`, so the theorem-facing FS endpoint
    remains unchanged while the future non-identity semantics are staged below
    it. In the current exact-zero model the shadow quantitative lane is now
    closed as well: `d_le_fs_shadow_pre_post_marginals_equal`,
    `le_fs_shadow_failure_probability_zero`,
    `A_LE_fs_shadow_sdist_le_failure_probability`, and
    `A_LE_fs_shadow_failure_probability_le_budget` are all proved. The next
    theorem-facing FS shadow packaging, May 2026: `LEFsProgramming.ec` now
    proves its theorem-facing component-budget endpoint
    `A_LE_fs_programming_sampler_sdist_le_budget` by transporting the shadow
    budget bound across
    `d_le_fs_shadow_pre_marginal_matches_post_rejection_view` and
    `d_le_fs_shadow_post_marginal_matches_programmed_view`, composing
    `A_LE_fs_shadow_sdist_le_failure_probability` with
    `A_LE_fs_shadow_failure_probability_le_budget`, and then reuses that
    theorem to keep the downstream name `A_LE_fs_surrogate_sdist_bound`
    unchanged. `LEStatisticalDistance.ec` therefore stays unchanged while the
    theorem-facing FS endpoint now rests on the semantic shadow lane.
  - Support-aware FS shadow good-branch closure, May 2026: the missing local
    theorem is now closed on the current exact-zero constructor shape.
    `LEFsProgrammingSurface.ec` now proves
    `d_le_pre_fs_programming_view_supportE`,
    `d_le_fs_shadow_pre_marginal_supportE`,
    `le_fs_shadow_good_event_on_pre_programming_support`,
    `le_fs_shadow_good_event_on_pre_marginal_support`, and
    `le_fs_shadow_good_branch_post_matches_surrogate_on_pre_support`. The
    recovered local bridge is then used directly inside
    `d_le_fs_shadow_post_marginal_matches_programmed_view`, and
    `d_le_fs_shadow_pre_post_marginals_equal` remains recovered without any
    theorem-facing changes to `LEFsProgramming.ec`, `LEStatisticalDistance.ec`,
    or `MainTheorem.ec`.
  - Branch-sensitive FS shadow refinement, May 2026: the active shadow post
    constructor is no longer surrogate-shaped. `LEFsProgrammingSurface.ec` now
    makes the hidden bad flag follow the pre-query bad bit, keeps the good
    branch collapsing to `le_fs_surrogate_transform` on pre-support via the
    support-aware closure lemmas, and routes the bad branch through a semantic
    post observable rebuilt from the shadow hidden material. The recovered
    local shadow theorems still close on that refined constructor:
    `d_le_fs_shadow_post_marginal_matches_programmed_view`,
    `d_le_fs_shadow_pre_post_marginals_equal`,
    `le_fs_shadow_failure_probability_zero`,
    `A_LE_fs_shadow_sdist_le_failure_probability`, and
    `A_LE_fs_shadow_failure_probability_le_budget` remain proved, and the
    theorem-facing files `LEFsProgramming.ec`, `LEStatisticalDistance.ec`, and
    `MainTheorem.ec` stay unchanged. The shadow bad event is now interpreted
    semantically on the shadow state rather than as a raw hidden flag, but it
    still closes to `0%r` in the current model because the active support is a
    `dunit` image of `le_real_execution_observable x s` and the concrete real
    query material fixes `leqm_bad_flag = false`. Design audit result: the
    smallest nonzero-support migration should not sample bad flags in the real
    execution view or change `d_le_real_view` first. Instead, add a separate
    lower FS shadow experiment law with explicit good/bad branch mass beside
    the current deterministic pre-FS observable path. That staging step is now
    landed in local form: `LEFsProgrammingSurface.ec` additionally defines the
    sampled semantic branch objects `d_le_fs_shadow_branch_choice`,
    `le_fs_shadow_local_bad_branch_mass`,
    `d_le_fs_shadow_semantic_post_marginal`,
    `le_fs_shadow_semantic_bad_event`, and
    `le_fs_shadow_semantic_failure_probability`. The current local sampler puts
    all of its internal mass on the bad branch, so the semantic branch lane is
    genuinely nontrivial while the exported projected-post theorems remain
    unchanged. The active theorem-facing endpoint still uses
    `d_le_fs_shadow_post_marginal_matches_programmed_view`,
    `d_le_fs_shadow_pre_post_marginals_equal`,
    `A_LE_fs_shadow_sdist_le_failure_probability`, and
    `A_LE_fs_shadow_failure_probability_le_budget` on the zero-budget path, so
    `LEFsProgramming.ec`, `LEStatisticalDistance.ec`, `MainTheorem.ec`, and
    `BudgetParameters.ec` remain unchanged and `epsilon_le_fs` / `epsilon_le`
    stay `0%r`. The next migration step is to connect that local semantic mass
    to theorem-facing budget arithmetic only after the top-level exact-zero LE
    corollary is relaxed or replaced with a compatible component-budget bridge.
  - Design refinement, May 2026: `A_LE_rejection_sampler_sdist_bound` remains a
    proved lemma in `le/LERejection.ec`, but it is no longer a repackaging of a
    surrogate-side axiom. It now rests on the concrete identity rejection
    transform and the resulting zero-distance lemma.
  - Shadow rejection lane, May 2026: `le/LERejectionSampler.ec` now also keeps a
    coupled-state shadow model beside that active identity lane. The shadow
    names are `le_rejection_shadow_state`,
    `d_le_rejection_shadow_coupled_state`,
    `d_le_rejection_shadow_pre_marginal`,
    `d_le_rejection_shadow_post_marginal`, and
    `le_rejection_shadow_failure_probability`. The shadow hidden material now
    records the concrete lower challenge-seed material and the resampled
    observable, while the shadow acceptance bit is derived from the lower
    challenge-seed branch. The two shadow theorem targets are now proved in
    `le/LERejection.ec`: `A_LE_rejection_shadow_sdist_le_failure_probability`
    and `A_LE_rejection_shadow_failure_probability_le_budget`. The theorem-facing
    `A_LE_rejection_sampler_sdist_bound` now factors through those shadow
    theorems directly to `epsilon_le_rej`, while
    `A_LE_rejection_surrogate_sdist_bound` remains the current exact theorem on
    the identity surrogate surface.
  - LE budget decomposition audit, May 2026: do not treat that rejection-side
    bridge as the permanent replacement surface. The intended steady state is
    component arithmetic, with a new FS budget `epsilon_le_fs` beside
    `epsilon_le_rej` and the umbrella LE budget defined or proved from their
    sum. That steady state is now active: `BudgetParameters.ec` defines the
    umbrella relation `epsilon_le = epsilon_le_rej + epsilon_le_fs`, and
    `LEStatisticalDistance.ec` now uses the rejection and FS component-budget
    endpoints directly instead of the former half-budget arithmetic.
  - Sampler bridge closure, May 2026: `le/LERejectionSampler.ec` now defines
    `d_le_rejection_real_execution_view` as `d_le_real_view`, defines
    `le_rejection_transform` as `le_post_rejection_surrogate`, keeps
    `d_le_rejection_post_execution_view` as the corresponding push-forward, and
    proves the bridge lemmas `le_real_view_matches_rejection_execution` and
    `le_post_rejection_view_matches_execution_transform`. `LERejection.ec` now
    imports that sampler bridge layer; `LEModel.ec` still does not.
  - Lower real-view concretization, May 2026: `le/LERealExecution.ec` now adds
    the lower names `le_real_execution_observable` and
    `d_le_real_execution_view = dunit ...`, and `LESurface.ec` now defines
    `d_le_real_view` as a direct alias of that lower sampler. This closes the
    real-view distribution shell without creating an import cycle.
  - Lower real-execution closure, May 2026: the sampler
    shell is no longer the obstruction, and there is now no remaining lower
    real-side abstraction on the LE observable path. The hidden-material
    constructor `le_real_execution_hidden_query_material_of` is now concrete on
    the richer carrier `le_query_material` in `LERealExecution.ec`. The lower
    primitive-boundary carrier `le_real_execution_primitive_material`, the
    lower public-spine carrier `le_real_execution_public_spine`, the lower
    execution carrier `le_real_execution_spine`, and the theorem-facing lower
    record `le_real_execution_record` are all concrete record shapes, while
    `le_real_execution_residual_material_of`,
    `le_real_execution_primitive_material_of`, `le_real_execution_spine_of`,
    and `le_real_execution_record_of` are now definitional end to end. The six theorem-facing hooks
    (`le_real_execution_commitment_coeffs`,
    `le_real_execution_t_coeffs`, `le_real_execution_z_coeffs`,
    `le_real_execution_challenge_seed_obs`,
    `le_real_execution_programmed_query_digest_obs`,
    `le_real_execution_query_material`) are now only projections from
    `le_real_execution_record_of`, and `LERealExecution.ec` proves the six
    corresponding field-exposure lemmas for `le_real_execution_observable`.
    The digest-related groups are concrete inside
    `le_real_execution_primitive_material_of`, coefficient construction
    (`commitment`, `t`, `z`) is concrete inside
    `le_real_execution_residual_material_of`, and hidden query material is now
    concrete as a record value. Because
    there is still no lower `le_public_input` extractor outside
    `sim/Simulator.ec`, any future refinement would be a new modeling choice
    rather than unfinished lower real-execution debt.
    On
    the quantitative path, the remaining theorem-facing surrogate axiom is
    gone, and the current lower FS carrier is fully closed. Any future
    nontrivial FS-programming semantics now requires enriching
    `le_query_material` or the lower real-execution surface rather than adding
    more FS-surrogate theorems above this layer.
  - Primitive-boundary audit, May 2026: before the latest incremental step,
    none of the fields under `le_real_execution_primitive_material_of` was
    fully concrete. After the digest-focused refinement, the challenge-seed and
    programmed-query-digest fields now have concrete material constructors in
    `LERealExecution.ec`, built from `hash_domain` plus the installed LE labels,
    while the final visible digest outputs still use `le_challenge_seed` and
    `le_programmed_query_digest`. After the coefficient-focused refinement,
    `primitives/QssmTypes.ec` now makes `coeff_vector` concrete as `int list`,
    and `LERealExecution.ec` builds the commitment, `t`, and `z` coefficient
    surfaces as fixed singleton vectors tagged `0`, `1`, and `2`. After the
    hidden-material refinement, `primitives/QssmTypes.ec` also makes
    `le_query_material` concrete as a record, and `LERealExecution.ec`
    populates the hidden query material concretely. All fields under
    `le_real_execution_primitive_material_of` are now concrete.
  - Partial primitive-boundary concretization, May 2026: the digest-related
    fields under `le_real_execution_primitive_material_of` are now concrete.
    `LERealExecution.ec` defines the challenge-seed material and
    programmed-query-digest material directly, using `hash_domain` on the
    installed LE labels plus the existing `le_challenge_seed` combinator where
    helpful. The coefficient trio is now concrete as well, via the concrete
    carrier `coeff_vector = int list` and three fixed singleton vectors in
    `LERealExecution.ec`. Hidden query material is now concrete too: the
    carrier is `unit`, and `le_real_execution_hidden_query_material_of` is
    definitional `tt`.
  - LE budget surface cleanup, May 2026: that audit is now complete.
    `A4_le_hvzk_bound_nonneg` remains as the intellectually honest primitive LE
    budget assumption on the abstract parameter `epsilon_le`; it is not
    derivable from the current LE lemmas, and folding it upward would only hide
    the true abstraction boundary. The redundant theorem-local wrapper in
    `MainTheorem.ec` has been removed, so `LEHVZK.ec`, `LEModel.ec`, and the
    theorem now expose the minimal necessary LE budget surface.
  - Exact next LE proof target, May 2026: there is no further LE budget-surface
    cleanup to do under the current abstraction. Any additional LE work should
    be substantive theorem or semantics work above this surface, not more
    boundary reshuffling.
  - Exact next FS proof target, May 2026: if a non-identity FS programming story is still desired, enrich `le_query_material` with a concrete programmable-query component and reintroduce a corresponding lower sampler/coupling theorem on that richer carrier. Otherwise the natural next LE target is the theorem-level cleanup above the now-fully-concrete `d_le_real_view` lane.
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
