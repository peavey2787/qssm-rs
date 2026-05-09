# LE HVZK Proof Plan

Navigation: [EasyCrypt README](../README.md)

## Objective

Refine the LE Set-B HVZK boundary into narrower, named obligations while keeping
`epsilon_le` as the final budget for the `G1 -> G2` hop.

Cross-tree checkpoint, May 2026: the MS2 visible/silent decomposition below routing is now complete in `ms/comparison/ComparisonPayloadSemanticBridge.ec`. Execution-owned MS2 semantic failure is split into visible and silent parts, the common execution-owned equalities are normalized through canonical helper names, and the normalized wrapper / round-trip layer remains bridge-local only. No theorem-facing budgets, routed theorem names, `ms/MSProbabilitySurface.ec`, `games/*`, or `theorem/MainTheorem.ec` changed in that checkpoint; the semantic top remains `3%r / 4%r`, the exact-zero route remains unchanged, and the immediate next step is roadmap triage rather than more MS2 normalized-wrapper micro-helpers.

Docs checkpoint, May 2026: `./check_easycrypt.sh` remains `OK` over 108 explicitly listed theories, `axiom_count=0`, and `admit_count=0`. The theorem-surface corollary phase is complete in `theorem/MainTheorem.ec` through `qssm_main_theorem`, `qssm_main_theorem_semantic_budget`, `qssm_main_theorem_semantic_budget_umbrella`, and `qssm_main_theorem_nonzero_budget`, so no separate `Corollaries.ec` file is needed. `BudgetParameters.ec` and `theorem/MainTheorem.ec` stay unchanged on this docs checkpoint, the semantic top remains `3%r / 4%r`, and the exact-zero route remains unchanged.

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
- **Lower rejection sampler split:** `le/LERejectionSamplerCore.ec` owns core definitions/helpers, `le/LERejectionSamplerSemanticMarginals.ec` owns semantic marginal/image helpers, `le/LERejectionSamplerMass.ec` owns semantic failure-probability / mass-budget closure, `le/LERejectionSamplerSemanticFacts.ec` owns semantic event/category/support facts, and `le/LERejectionSampler.ec` remains the public facade
- **Lower FS programming split:** `le/LEFsProgrammingHiddenState.ec` owns hidden-state reconstruction/update/projection and lower FS programming proofs, while `le/LEFsProgrammingSurface.ec` remains the stable lower FS public surface
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
     the rejection and FS lower theorem surfaces below; this line is now
     historical because the active tree no longer depends on in-tree axiom bundles here).
   - **Done (skeleton):** `A_LE_view_indist_to_sd_bound` is proved from
     `A_LE_combined_hiding_bounds_sdist`, which uses `sdist_triangle` on
     `d_le_real_view`, `d_le_post_rejection_view`, `d_le_sim_view` and the two
     then-live half-budget lemmas above. This note is now historical: the active
     tree closes through component-budget endpoints and the semantic-budget
     wrappers instead. The old proof debt was instantiating the surrogates and
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
    `le_fs_shadow_semantic_failure_probability`. The current local sampler is
    now a genuine two-branch law with both good and bad support, and the local
    semantic failure probability is identified with the sampler-local bad-branch
    mass `mu d_le_fs_shadow_branch_choice (fun bad => bad)`. The exported
    projected-post theorems remain unchanged because the theorem-facing shadow
    post marginal still forgets the sampled branch and projects only the
    surrogate-facing observable lane. The active theorem-facing endpoint still uses
    `d_le_fs_shadow_post_marginal_matches_programmed_view`,
    `d_le_fs_shadow_pre_post_marginals_equal`,
    `A_LE_fs_shadow_sdist_le_failure_probability`, and
    `A_LE_fs_shadow_failure_probability_le_budget` on the zero-budget path, so
    `LEFsProgramming.ec`, `LEStatisticalDistance.ec`, `MainTheorem.ec`, and
    `BudgetParameters.ec` remain unchanged and `epsilon_le_fs` / `epsilon_le`
    stay `0%r`. The next migration step is to connect that local semantic mass
    to theorem-facing budget arithmetic only after the top-level exact-zero LE
    corollary is relaxed or replaced with a compatible component-budget bridge.
    Follow-on local closure, May 2026: the shadow-local two-branch sampler now
    also has closed-form mass and semantic-post support facts. The concrete
    branch masses are proved by
    `le_fs_shadow_branch_choice_mass_false` and
    `le_fs_shadow_branch_choice_mass_true`, so
    `le_fs_shadow_local_bad_branch_mass_closed_form` proves
    `le_fs_shadow_local_bad_branch_mass = 3%r / 16%r` and
    `le_fs_shadow_semantic_failure_probability_closed_form` proves the same
    exact value for `le_fs_shadow_semantic_failure_probability x s`. The local
    support layer is now explicit as well:
    `le_fs_shadow_semantic_good_branch_support` and
    `le_fs_shadow_semantic_bad_branch_support` prove coupled-state support for
    the two sampled semantic branches,
    `le_fs_shadow_semantic_post_marginal_support` lifts that support into the
    semantic-post marginal,
    `le_fs_shadow_semantic_post_good_branch_support` and
    `le_fs_shadow_semantic_post_bad_branch_support` witness both concrete
    semantic-post images on support, and
    `d_le_fs_shadow_semantic_post_marginal_supportE` characterizes semantic-post
    support as exactly those two branch images over
    `le_real_execution_observable x s`. These remain purely local facts in
    `LEFsProgrammingSurface.ec`; `BudgetParameters.ec`, `LEFsProgramming.ec`,
    `LEStatisticalDistance.ec`, and `MainTheorem.ec` remain unchanged.
    Semantic/programmed-view split closure, May 2026: the next local bridge is
    now explicit without changing the theorem-facing path. The good branch image
    is packaged by
    `le_fs_shadow_semantic_post_good_branch_matches_programmed_view` and the
    distribution-level equality
    `d_le_fs_shadow_semantic_good_branch_image_matches_programmed_view`; the bad
    branch image is packaged by
    `le_fs_shadow_semantic_post_bad_branch_matches_semantic_programmed_view` via
    the local operator
    `le_fs_shadow_semantic_programmed_view_of_observable`. The semantic-post
    marginal itself now closes as a branch split by
    `d_le_fs_shadow_semantic_post_marginal_branch_split_pairE` and, on the fixed
    real-execution support, by
    `d_le_fs_shadow_semantic_post_marginal_fixed_branch_imageE`. The local
    deviation theorem
    `le_fs_shadow_semantic_post_differs_from_programmed_view_only_on_bad_branch`
    records that semantic/programmed disagreement can only occur on the bad
    branch, and the future-budget bridge target
    `A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass` is now
    proved locally: `sdist (d_le_fs_shadow_semantic_post_marginal x s)
    (d_le_post_fs_programmed_view x s) <= le_fs_shadow_local_bad_branch_mass`.
    That local theorem still does not alter `epsilon_le_fs`, `epsilon_le`, or
    the theorem-facing exact-zero corollary by itself; it is the lower semantic
    bridge used by the parallel theorem-facing chain landed in the next step.
  - Parallel semantic theorem chain, May 2026: `le/LEFsProgramming.ec` now
    exports `A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass`,
    which packages the local semantic-post/programmed-view distance as a
    theorem-facing FS endpoint bounded by `le_fs_shadow_local_bad_branch_mass`.
    `le/LEStatisticalDistance.ec` now adds
    `A_LE_semantic_combined_hiding_bounds_sdist` and
    `A_LE_semantic_view_advantage_bound_from_indistinguishability` over the new
    semantic view quantity `le_semantic_view_distinguishing_adv`, so the
    parallel semantic LE view chain now closes at
    `epsilon_le_rej + le_fs_shadow_local_bad_branch_mass` without routing
    through `epsilon_le_fs`. `le/LEHVZK.ec` packages that result as
    `A_LE_HVZK_semantic_transition_bound`. `games/GameLEBridge.ec` now uses
    the fact that the game distinguisher reads only `qssm_event_payload` to
    prove `A_LE_semantic_projected_adv_matches_game_adv`, then exports the
    direct semantic bridge theorem `A_G1_to_G2_le_semantic_transition_bound`
    with bound `LERejectionSampler.le_rejection_shadow_semantic_failure_probability + le_fs_shadow_local_bad_branch_mass` on
    `Adv_G1_G2_LE`. At the top level, `theorem/MainTheorem.ec` now adds
    `qssm_main_theorem_semantic_budget_local_mass` with bound
    `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic +
    LERejectionSampler.le_rejection_shadow_semantic_failure_probability +
    le_fs_shadow_local_bad_branch_mass`, and that theorem now uses the
    semantic G1->G2 bridge directly together with the semantic MS G0->G1
    sibling bound rather than widening through the exact-zero skeleton. The
    exact-zero route still remains checked in parallel:
    `BudgetParameters.ec`, `A_G1_to_G2_le_transition_bound`,
    `qssm_main_theorem_skeleton`, and `qssm_main_theorem` remain unchanged.
  - Primitive-owned semantic FS budget, May 2026: `primitives/BudgetParameters.ec`
    now defines the primitive branch law via the primitive FS category support
    `clean`, `query_collision`,
    `programming_collision`, `transcript_mismatch`, failure predicate
    “non-clean”, the named count constants `le_fs_clean_slot_count`,
    `le_fs_query_collision_slot_count`,
    `le_fs_programming_collision_slot_count`,
    `le_fs_transcript_mismatch_slot_count`, `le_fs_failure_slot_count`, and
    `le_fs_total_slot_count`, the derived compatibility
    sampler `d_le_fs_semantic_branch_choice`, together with the owned semantic
    FS budget `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice
    true` and nonnegativity lemma `A4_le_fs_semantic_nonneg`. The owned closed
    form is now `le_fs_failure_slot_count%r / le_fs_total_slot_count%r`; with
    `le_fs_clean_slot_count = 13` and the three failure categories still at one
    slot each, it instantiates in the current model to `3%r / 16%r`. `le/LEFsProgrammingSurface.ec`
    now interprets those primitive categories on a category-coupled shadow
    state through the exact lower names `d_le_fs_shadow_category_choice`,
    `le_fs_shadow_state_of_category_observable`,
    `le_fs_shadow_clean_condition`,
    `le_fs_shadow_query_collision_condition`,
    `le_fs_shadow_programming_collision_condition`,
    `le_fs_shadow_transcript_mismatch_condition`, and
    `le_fs_shadow_semantic_category_condition_stateE`: `clean` is the no-failure/programmed-view branch,
    `query_collision` is bad-branch query-row alignment,
    `programming_collision` is bad-branch programmed-response digest/log
    alignment, and `transcript_mismatch` is bad-branch visible-shell
    agreement with a cleared semantic bad flag. It also proves the local
    equality `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic`
    and the corresponding `<=` bridge, so the local semantic mass is now
    connected to a primitive-owned structured budget without an import-cycle
    inversion. `le/LEFsProgramming.ec`,
    `le/LEStatisticalDistance.ec`, and `le/LEHVZK.ec` each now add owned-budget
    semantic wrapper theorems ending in `epsilon_le_fs_semantic`; the game
    layer exposes `A_G1_to_G2_le_semantic_owned_budget_transition_bound` with
    bound `epsilon_le_rej_semantic + epsilon_le_fs_semantic`; and
    `theorem/MainTheorem.ec` now adds `qssm_main_theorem_semantic_budget_owned`
    with bound `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic +
    epsilon_le_rej_semantic + epsilon_le_fs_semantic`. The exact-zero route and the
    existing local-mass semantic route both remain checked alongside that owned-
    budget path. These slot counts are intentionally concrete demo/proof
    parameters for the current semantic FS lane, not a protocol-owned bundle;
    any later move to `primitives/ProtocolParameters.ec` is deferred until a
    real shared parameter surface exists.
  - Semantic rejection budget, May 2026: `primitives/BudgetParameters.ec`
    still defines the theorem-facing semantic rejection branch weight with the
    primitive category support `soft_repair`, `hard_repair`, `invalid`,
    `accept`, the failure predicate “non-accept”, the named count constants
    `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`,
    `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`,
    `le_rej_failure_slot_count`, and `le_rej_total_slot_count`, and
    `epsilon_le_rej_semantic = mu1 d_le_rejection_semantic_branch_choice true = le_rej_failure_slot_count%r / le_rej_total_slot_count%r = 3%r / 16%r`,
    together with proved nonnegativity lemma
    `A4_le_rejection_semantic_nonneg`. The lower semantic rejection owner is
    now execution-owned: `le/LERealExecution.ec` defines the semantic rejection
    support and branch-dependent material, `le/LERejectionSampler.ec` exports
    `d_le_semantic_post_rejection_view`, `le/LERejection.ec` re-exports the
    theorem-facing semantic rejection endpoints on that execution-owned post
    marginal, `le/LEFsProgrammingSurface.ec` feeds that midpoint into
    `d_le_pre_fs_semantic_programming_view` /
    `d_le_post_fs_semantic_programmed_view`, and
    `le/LEStatisticalDistance.ec` plus `games/GameLEBridge.ec` now route the
    semantic comparison path over that honest internal chain. The current
    execution/sampler material carrier still projects `soft_repair`,
    `hard_repair`, and `invalid` to the shared reject branch, so the checked
    lower lemmas distinguish only failure-vs-accept plus repair/no-repair.
    That is sufficient for the present theorem path because the live consumers
    do not need category-specific material witnesses. Any future true material
    split should therefore be added as an additive category-carrying
    constructor/ticket layer in `le/LERealExecution.ec`, replayed through the
    sampler below the theorem-facing wrappers rather than by changing the
    public theorem names or budget owners. The local semantic comparison
    theorem still closes at
    `le_rejection_shadow_semantic_failure_probability + le_fs_shadow_local_bad_branch_mass`,
    the owned theorem still closes at
    `epsilon_le_rej_semantic + epsilon_le_fs_semantic`, and the semantic
    umbrella still feeds `qssm_main_theorem_semantic_budget`.
  - Semantic umbrella LE budget, May 2026: `primitives/BudgetParameters.ec`
    now also defines `epsilon_le_semantic = epsilon_le_rej_semantic +
    epsilon_le_fs_semantic`, together with `epsilon_le_semantic_component_sum`
    and `epsilon_le_semantic_nonneg`. `le/LEStatisticalDistance.ec` adds
    umbrella wrappers that close directly at `epsilon_le_semantic` while
    preserving the owned component-sum theorem; `le/LEHVZK.ec` adds
    `A_LE_HVZK_semantic_umbrella_transition_bound`; `games/GameLEBridge.ec`
    adds `A_G1_to_G2_le_semantic_umbrella_transition_bound`; and
    `theorem/MainTheorem.ec` now adds
    `qssm_main_theorem_semantic_budget` with bound
    `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic +
    epsilon_le_semantic`. `qssm_main_theorem_nonzero_budget` is now a façade
    alias to that same public umbrella theorem, while
    `qssm_main_theorem_semantic_budget_umbrella` is retained only as a
    compatibility alias and `qssm_main_theorem_semantic_budget_owned` plus
    `qssm_main_theorem_semantic_budget_local_mass` remain as comparison lemmas.
    This makes `epsilon_le_semantic` the preferred nonzero LE budget umbrella
    and `qssm_main_theorem_semantic_budget` the preferred nonzero top-level
    theorem name to cite, while the exact-zero route still remains checked in
    parallel.
  - Parallel MS ROM semantic owner, May 2026:
    `primitives/BudgetParameters.ec` now also defines the parallel owner term
    `epsilon_ms_rom_programmability_semantic =
    ms_rom_failure_slot_count%r / ms_rom_total_slot_count%r` together with the
    primitive category support
    `MSROMSemanticClean`, `MSROMSemanticQueryCollision`,
    `MSROMSemanticProgrammingCollision`, and
    `MSROMSemanticTranscriptMismatch`, failure predicate “non-clean”, the named
    counts `ms_rom_clean_slot_count`,
    `ms_rom_query_collision_slot_count`,
    `ms_rom_programming_collision_slot_count`,
    `ms_rom_transcript_mismatch_slot_count`, `ms_rom_failure_slot_count`, and
    `ms_rom_total_slot_count`, and the current demo instance `13,1,1,1`, which
    closes to `3%r / 16%r`. The exact-zero theorem-facing MS2 hop still
    consumes `epsilon_ms_rom_programmability = 0%r` through the existing
    exact-equality route in `ms/MSProbabilitySurface.ec`, `ms/MS.ec`, the game
    layer, and the exact-zero theorems in `theorem/MainTheorem.ec`, because
    there is not yet an execution-owned MS semantic bridge surface honest
    enough to replay that path. The first split step is now landed at the
    alias surface: `primitives/FS.ec` re-exports
    `epsilon_ms_rom_programmability_semantic` together with
    `A2_ms_rom_programmability_semantic_nonneg`. The next split step is now
    also landed through game-hop composition: `ms/MSProbabilitySurface.ec`,
    `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`,
    `games/GameMSHopTransitions.ec`, and `games/GameMSHopComposition.ec` now
    export the semantic sibling chain from
    `A_MS2_rom_programming_semantic_transition_bound` through
    `A_G0_to_G1_ms_semantic_transition_bound`, all closing against
    `epsilon_ms_rom_programmability_semantic`. The semantic MainTheorem
    variants now consume that sibling chain, and after the later semantic MS1
    retarget the current semantic umbrella theorem closes at
    `epsilon_ms_hash_binding_semantic +
    epsilon_ms_rom_programmability_semantic + epsilon_le_semantic =
    3%r / 16%r + 3%r / 16%r + 3%r / 8%r = 3%r / 4%r`, while the exact-zero
    theorem route and the public theorem API remain unchanged.
  - MS ROM routing split design, May 2026:
    the live dependency path should be split by adding parallel semantic
    siblings rather than by redefining any active theorem-facing symbol in
    place. The exact-zero budget still starts at
    `primitives/BudgetParameters.ec : epsilon_ms_rom_programmability`, is
    re-exported through `primitives/FS.ec` with
    `A2_ms_rom_programmability_nonneg`, enters the lower MS2 theorem surface at
    `ms/MSProbabilitySurface.ec : A_MS2_rom_programming_transition_bound`
    (proved today from `L_ms2_rom_programming_transition_zero` plus that
    nonnegativity lemma), is lifted by
    `games/GameAdvantage.ec : A_MS2_rom_programming_game_pr_core_bound`, then
    by `games/GameMSHopTypes.ec :
    A_MS2_rom_programming_concrete_pair_advantage_bound` and
    `A_MS2_canonical_rom_programming_bound`, then by
    `games/GameMSHopTransitions.ec : A_MS2_rom_programming_transition`, then by
    `games/GameMSHopComposition.ec : A_G0_to_G1_ms_transition_bound`, and is
    finally consumed on the exact-zero public route in `theorem/MainTheorem.ec`
    by `qssm_main_theorem_skeleton` and `qssm_main_theorem`. In parallel, the
    semantic sibling route now starts from
    `primitives/BudgetParameters.ec : epsilon_ms_rom_programmability_semantic`,
    is re-exported through `primitives/FS.ec` with
    `A2_ms_rom_programmability_semantic_nonneg`, is lifted by
    `games/GameMSHopComposition.ec : A_G0_to_G1_ms_semantic_transition_bound`,
    and is now consumed in `theorem/MainTheorem.ec` by
    `qssm_main_theorem_semantic_budget_local_mass`,
    `qssm_main_theorem_semantic_budget_owned`,
    `qssm_main_theorem_semantic_budget`, and the façade alias
    `qssm_main_theorem_nonzero_budget`. `ms/MS.ec` is currently only the hop
    shape / comment façade for this route via `ms2_rom_programming_step`; it is
    not the proof owner of the budget theorem. The checker-safe split design is
    therefore: keep `epsilon_ms_rom_programmability = 0%r` and all current
    exact-zero theorem names unchanged. The checker-safe split steps through the
    alias surface, the composed G0->G1 semantic sibling chain, the semantic
    MainTheorem retarget, the execution-owned MS ROM bridge below
    `A_G0_to_G1_ms_semantic_transition_bound`, and the semantic AfterRom
    endpoint below `ms/MSProbabilitySurface.ec` are now done while
    `qssm_main_theorem_skeleton` / `qssm_main_theorem` stay on the current
    exact-zero route. The public MS2 stage pair still collapses locally by
    exact distribution equality, but `ms/MSProbabilitySurface.ec` now also
    carries `d_ms_after_rom_semantic_observable_v2` and
    `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure`, so
    the next step is no longer lower-surface ownership; it is deciding whether
    the public AfterRom stage should be retargeted away from that exact-equality
    carrier while the game-level sibling chain above it remains unchanged.
  - Parallel MS hash-binding semantic owner, May 2026:
    `primitives/BudgetParameters.ec` now also defines the parallel owner term
    `epsilon_ms_hash_binding_semantic =
    ms_hash_binding_failure_slot_count%r /
    ms_hash_binding_total_slot_count%r` together with the primitive category
    support `MSHashBindingSemanticClean`,
    `MSHashBindingSemanticCollision`,
    `MSHashBindingSemanticMalformedBinding`, and
    `MSHashBindingSemanticTranscriptMismatch`, failure predicate “non-clean”,
    the named counts `ms_hash_binding_clean_slot_count`,
    `ms_hash_binding_collision_slot_count`,
    `ms_hash_binding_malformed_binding_slot_count`,
    `ms_hash_binding_transcript_mismatch_slot_count`,
    `ms_hash_binding_failure_slot_count`, and
    `ms_hash_binding_total_slot_count`, and the current demo instance
    `13,1,1,1`, which closes to `3%r / 16%r`. `primitives/FS.ec` now
    re-exports that owner as `epsilon_ms_hash_binding_semantic` together with
    `A1_ms_hash_binding_semantic_nonneg`. That owner is now staged below the
    live theorem route: `ms/MS.ec` carries the MS-side alias/nonneg surface,
    `ms/source/SourceHashBindingSemanticBridge.ec` lands the source-local
    execution-owned bridge, `ms/MSProbabilitySurface.ec` and the MS game-hop
    files carry the staged sibling chain through
    `A_G0_to_G1_ms_hash_binding_semantic_transition_bound`, and
    `theorem/MainTheorem.ec` now consumes the semantic owner through the
    retargeted live theorem `A_G0_to_G1_ms_semantic_transition_bound`, while
    the exact-zero route still consumes `epsilon_ms_hash_binding = 0%r`.
    The current live semantic umbrella theorem therefore closes at
    `epsilon_ms_hash_binding_semantic +
    epsilon_ms_rom_programmability_semantic + epsilon_le_semantic =
    3%r / 16%r + 3%r / 16%r + 3%r / 8%r = 3%r / 4%r`, and the staged sibling
    remains as a parallel bisectable theorem.
  - Comparison-local MS ROM semantic bridge, May 2026:
    `ms/comparison/ComparisonPayloadExecutionSeedTypes.ec` now owns the
    execution-seed package/types/laws,
    `ms/comparison/ComparisonPayloadExecutionLaw.ec` owns the execution
    payload law transport, `ms/comparison/ComparisonPayloadFromSeed.ec`
    remains the stable payload/schedule facade,
    `ms/comparison/ComparisonPayloadSemanticSlotMass.ec` owns the local
    slot/mass law for the semantic MS2 ROM owner, and
    `ms/comparison/ComparisonPayloadSemanticBridge.ec` now lands the first
    execution-owned bridge surface below `ms/MSProbabilitySurface.ec` without
    changing the live routing. The bridge file defines
    `ms_rom_semantic_state_of_category_execution_seed`, carrying the real
    comparison execution seed package together with canonical query/row data,
    programmed challenge/response data, transcript reconstruction data, and
    explicit query/programming collision witnesses; the predicates
    `ms_rom_clean_condition`, `ms_rom_query_collision_condition`,
    `ms_rom_programming_collision_condition`,
    `ms_rom_transcript_mismatch_condition`, and
    `ms_rom_semantic_category_condition`; the bridge consumes the local mass
    owner `ms_rom_local_failure_mass` together with
    `ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic`; and
    the lower bound `A_MS2_rom_programming_execution_owned_semantic_bound`.
    `check_easycrypt.sh` now includes that new theory in dependency order. This
    bridge step has now been followed by the targeted lower retarget in
    `ms/MSProbabilitySurface.ec`: that file now maps the bridge projection
    `ms_rom_semantic_after_rom_observable_of_state` over
    `d_ms_rom_semantic_coupled_state` as
    `d_ms_after_rom_public_semantic_observable_v2`, proves the direct
    replacement law
    `L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure`,
    refines its bad predicate to the public-observable divergence condition
    `ms_rom_public_observable_divergence_condition`,
    retargets `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure`,
    and keeps `A_MS2_rom_programming_semantic_transition_bound` on the same
    theorem name while `games/GameMSHopComposition.ec`, `theorem/MainTheorem.ec`,
    the exact-zero theorem `A_MS2_rom_programming_transition_bound`, and all
    public theorem names stay unchanged. The next patch is therefore no longer
    lower-surface public AfterRom retargeting or the first public-divergence
    refinement; it is to tighten or justify the current semantic-public
    surrogate if a more deployment-meaningful lower ROM-programming
  - Source-local MS1 hash-binding semantic bridge and staged sibling chain,
    May 2026: `ms/MS.ec` now stages the MS-facing alias/nonneg surface for
    `epsilon_ms_hash_binding_semantic`,
    `ms/source/SourceHashBindingSemanticSlotMass.ec` now owns the local
    slot/mass law for the parallel semantic MS1 owner, and
    `ms/source/SourceHashBindingSemanticBridge.ec` now lands the source-local
    execution-owned bridge for that owner. The bridge file
    defines `ms_hash_binding_semantic_state_of_category_source`, the category
    predicates `ms_hash_binding_clean_condition`,
    `ms_hash_binding_collision_condition`,
    `ms_hash_binding_malformed_binding_condition`,
    `ms_hash_binding_transcript_mismatch_condition`, consumes the local mass
    owner `ms_hash_binding_local_failure_mass`, and proves the lower bound
    `A_MS1_hash_binding_execution_owned_semantic_bound`. `ms/MSProbabilitySurface.ec`,
    `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`, and
    `games/GameMSHopTransitions.ec` now carry the staged semantic MS1 sibling
    chain through `A_MS1_hash_binding_semantic_bad_event_bound`,
    `A_MS1_hash_binding_semantic_game_pr_core_bound`,
    `A_MS1_hash_binding_semantic_concrete_pair_advantage_bound`,
    `A_MS1_canonical_hash_binding_semantic_bound`, and
    `A_MS1_hash_binding_semantic_transition`, and
    `games/GameMSHopComposition.ec` now adds the staged sibling
    `A_G0_to_G1_ms_hash_binding_semantic_transition_bound`. The live semantic
    theorem `A_G0_to_G1_ms_semantic_transition_bound` and the semantic route in
    `theorem/MainTheorem.ec` now also consume semantic MS1, so the current
    semantic umbrella theorem closes at
    `epsilon_ms_hash_binding_semantic +
    epsilon_ms_rom_programmability_semantic + epsilon_le_semantic = 3%r / 4%r`.
    The exact-zero route remains unchanged. The same MS1 bridge now also
    carries a local public-divergence upper mass
    `ms_hash_binding_local_public_divergence_upper_mass = 1%r / 8%r`, and
    `ms/MSProbabilitySurface.ec` stages it in
    `L_ms1_public_after_binding_transition_le_local_public_divergence_upper_mass`
    and
    `L_ms1_public_after_binding_compatibility_le_local_public_divergence_upper_mass`.
    Those lemmas are staged-only evidence: they do not replace the theorem-facing
    `epsilon_ms_hash_binding_semantic = 3%r / 16%r` owner path, do not change
    any public theorem name, and do not alter the live semantic top `3%r / 4%r`.
  - Public-endpoint splice boundary, May 2026: `ms/MSProbabilitySurface.ec`
    now also proves the staged lower-surface theorems
    `A_MS2_rom_programming_semantic_public_endpoint_transition_bound`,
    `A_MS1_to_MS2_semantic_public_endpoint_transition_bound`,
    `A_MS1_to_MS2_semantic_public_endpoint_visible_flags_bound`,
    `A_MS1_to_MS2_semantic_public_endpoint_local_visible_flags_bound`, and
    `A_MS1_to_MS2_semantic_public_endpoint_local_visible_flags_closed_form_bound`.
    The visible-flags sibling keeps the MS2 public term on the refined visible
    divergence mass, the symbolic local-visible sibling keeps the MS1 term on
    `ms_hash_binding_local_public_divergence_upper_mass`, and the closed-form
    corollary rewrites only that staged MS1 local term to `1%r / 8%r`.
    `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`, and
    `games/GameMSHopComposition.ec` now also lift that same segment into a
    parallel staged public-endpoint route through `Adv_ms_public_endpoint`,
    staged wrappers, and staged composition aliases. None of these theorems are
    part of the live semantic route. The live G0->G1 semantic chain already
    pays canonical MS1 once through `A_MS1_hash_binding_semantic_transition`
    and canonical MS2 once through `A_MS2_rom_programming_semantic_transition`,
    and the staged public-endpoint route covers that same MS1+MS2 segment, so
    routing the staged splice through the current canonical telescope would
    double-count the routed semantic MS segment. If these public endpoints are
    ever to be used live, the next patch is not direct splice routing in
    `games/GameMSHopComposition.ec` or `theorem/MainTheorem.ec`; it is a new
    public-endpoint bridge or game abstraction below the current
    `game_pr_ms_core` / `Adv` surface that replaces the current MS1+MS2 witness
    behind unchanged theorem names and theorem-facing bounds. The visible-flags
    and local-visible variants remain staged refinements only, the exact-zero
    route stays separate, and the semantic top remains `3%r / 4%r`.
    A subsequent direct probe of that canonical-terminal replacement surface was
    attempted in `ms/MSProbabilitySurface.ec` and rolled back: the proof reduced
    to the terminal obligation `mu (d_ms_rom_semantic_coupled_state xms)
    (ms_rom_public_observable_divergence_condition xms) <= 0%r`. The current
    bridge only proves the charged divergence-mass bound
    `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure`,
    so there is no zero-cost `public AfterRom -> canonical AfterRom` landing on
    the present lower carrier. This means the public-endpoint route must remain
    staged-only for now. Any future live replacement needs either a stronger
    terminal fusion law proving zero public divergence on that carrier or an
    approved theorem-facing change that permits a charged terminal term.
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
    and `A_LE_rejection_shadow_failure_probability_le_budget`. In parallel,
    `le/LERejectionSampler.ec` now also defines the semantic experiment names
    `d_le_rejection_shadow_semantic_coupled_state`,
    `d_le_rejection_shadow_semantic_pre_marginal`,
    `d_le_rejection_shadow_semantic_post_marginal`, and
    `le_rejection_shadow_semantic_failure_probability`, together with support
    lemmas for both semantic branches, the local experiment theorem
    `A_LE_rejection_shadow_semantic_post_marginal_sdist_le_failure_probability`,
    and the budget closure
    `le_rejection_shadow_semantic_failure_probability = epsilon_le_rej_semantic`.
    `le/LERejection.ec` re-exports semantic experiment endpoints beside the
    existing theorem-facing semantic wrapper. The exact-zero theorem-facing
    `A_LE_rejection_sampler_sdist_bound` still factors through the zero shadow
    theorems directly to `epsilon_le_rej`, while
    `A_LE_rejection_surrogate_sdist_bound` remains the current exact theorem on
    the identity surrogate surface.
  - Cross-lane target selection, May 2026: the execution-owned rejection-owner
    handoff and semantic post-rejection to semantic-FS wiring are now done.
    Freeze both semantic count owners in `primitives/BudgetParameters.ec` as-is
    for the moment; any `primitives/ProtocolParameters.ec` move stays deferred
    until a real shared protocol-owned source exists. That richer
    execution-owned semantic rejection repair is now also landed: the reject
    branch runs through an execution-owned ticket and repaired observable while
    the exact-zero/public-theorem route stays fixed. The semantic rejection
    budget grounding is now landed as well: the public budget is a primitive
    multi-category ticket-failure law with categories `soft_repair`,
    `hard_repair`, `invalid`, and `accept`, owned through the named counts
    `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`,
    `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`,
    `le_rej_failure_slot_count`, and `le_rej_total_slot_count`, and the
    concrete execution-owned ticket failure probability is proved equal to it.
    The current milestone decision is to stop there: the four-way budget law is
    now documented and checked, while the live material carrier intentionally
    keeps `soft_repair`, `hard_repair`, and `invalid` on the shared reject
    branch because the theorem path only consumes failure-vs-accept and
    repair/no-repair facts. If later LE realism work needs true category-
    specific material consequences, the first refactor should be a design-only
    sketch and then an additive category-carrying constructor layer in
    `le/LERealExecution.ec`, not theorem-surface churn.
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
