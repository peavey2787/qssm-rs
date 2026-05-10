# Proof Status

Navigation: [EasyCrypt README](../README.md)

## Snapshot

As of May 2026, the EasyCrypt tree under this directory checks cleanly with `./check_easycrypt.sh`; the current checker snapshot is `OK` over 135 checked theories; the repo-local named `axiom` count in `*.ec` files under this directory is `0`; and the current repo-local `admit` count is `0`.

The active theorem path is therefore fully machine-checked at the current abstraction boundary. The important caveat is now narrower: theorem routing is frozen at an exact-zero route, a demo semantic route, an LE-only intermediate parameterized route, and a full canonical parameterized route that closes through a charged public-to-canonical MS landing rather than a zero-cost identification.

Alongside that exact-zero path, the tree now carries three checked non-exact theorem-facing companions with different scope. `qssm_main_theorem_semantic_budget` is still the live demo semantic theorem and still closes at `3%r / 4%r` on the unchanged canonical/demo route. `qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate parameterized theorem: it keeps the canonical/demo MS contribution unchanged and swaps only the LE side to `GameLEBridgeParameterized.ec`. `qssm_main_theorem_parameterized_budget` is now the full canonical parameterized theorem. Its top budget is `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized`, which evaluates to `15%r / 32%r` on the active live profiles; the duplicated MS2 term is kept explicit because the public AfterRom observable is still only budget-close to the canonical AfterRom observable, not zero-equal.

The semantic MS owner is now also grounded by a comparison-local execution-owned bridge theory. `ms/comparison/ComparisonPayloadExecutionSeedTypes.ec` owns the execution-seed package/types/laws, `ms/comparison/ComparisonPayloadExecutionLaw.ec` owns the execution payload law transport, `ms/comparison/ComparisonPayloadFromSeed.ec` remains the stable payload/schedule facade, `ms/comparison/ComparisonPayloadSemanticSlotMass.ec` owns the local slot/mass law for the semantic MS2 ROM owner, and `ms/comparison/ComparisonPayloadSemanticBridge.ec` consumes that owner: it defines `ms_rom_semantic_state_of_category_execution_seed`, the category interpretation predicates and lemmas, the semantic AfterRom projection `ms_rom_semantic_after_rom_observable_of_state`, the semantic-public digest/observable projections `ms_after_rom_public_semantic_digest_of_state` and `ms_after_rom_public_semantic_observable_of_state`, the refined public-divergence predicate `ms_rom_public_observable_divergence_condition` together with its characterization lemmas and the mass bridge `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure`, and `A_MS2_rom_programming_execution_owned_semantic_bound`; `ms/MSProbabilitySurface.ec` now maps that public-semantic projection over `d_ms_rom_semantic_coupled_state` as `d_ms_after_rom_public_semantic_observable_v2`, proves `L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure` against that refined public-divergence predicate, retargets `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure` to that endpoint, and keeps `A_MS2_rom_programming_semantic_transition_bound` on the same theorem name while `games/GameMSHopComposition.ec` and `theorem/MainTheorem.ec` remain untouched in this step.

That MS2 bridge layer now also completes the visible/silent decomposition strictly below routing. Execution-owned MS2 semantic failure is split into visible and silent parts, the common execution-owned equalities are available through direct and dispatcher-derived routes and then normalized through canonical helper names, and the normalized wrapper / round-trip layer remains bridge-local only in `ms/comparison/ComparisonPayloadSemanticBridge.ec`. No theorem-facing budgets, routed theorem names, `ms/MSProbabilitySurface.ec`, `games/*`, or `theorem/MainTheorem.ec` changed in that micro-layer; the live semantic top remains `3%r / 4%r`, and the exact-zero route remains unchanged.

Beside that routed semantic MS2 surface, `BudgetParameters.ec` now also carries a parallel semantic MS1 hash-binding owner skeleton with categories `clean`, `collision`, `malformed_binding`, and `transcript_mismatch`, demo counts `13,1,1,1`, and owner term `epsilon_ms_hash_binding_semantic = 3%r / 16%r`. `primitives/FS.ec` re-exports it as `epsilon_ms_hash_binding_semantic`, `ms/MS.ec` now stages the MS-side alias/nonneg surface, `ms/source/SourceHashBindingSemanticSlotMass.ec` owns the local slot/mass law for that semantic MS1 owner, and `ms/source/SourceHashBindingSemanticBridge.ec` consumes that owner to give a source-local execution-owned bridge plus a staged lower/game sibling chain through `A_G0_to_G1_ms_hash_binding_semantic_transition_bound`. That same bridge now also proves a tighter local public-divergence upper mass `ms_hash_binding_local_public_divergence_upper_mass = 1%r / 8%r`, and `ms/MSProbabilitySurface.ec` stages that result in local-evidence lemmas only. The live semantic theorem route still consumes semantic MS1 through `A_G0_to_G1_ms_semantic_transition_bound`, so the theorem-facing MS1 owner remains `3%r / 16%r`, the exact-zero public route still consumes `epsilon_ms_hash_binding = 0%r`, and no public theorem or semantic-top value changes in this step.

## What the `0 axioms` Claim Means

`0 axioms` means there are currently no named `axiom` declarations in the EasyCrypt `*.ec` files under this directory.

It does not mean:

- the formalization is already a realistic nonzero cryptographic security reduction
- every modeling choice has been refined to a final semantic form
- the proof is already linked mechanically to the Rust implementation
- the standard library, checker, or code-to-model correspondence have disappeared as trust boundaries

What has happened is narrower and more precise:

- algebra and sampler closure work moved earlier repo-local assumptions into constructive owners or proved lemmas
- budget names were centralized and then replaced with concrete exact-zero definitions in the current model
- lower rejection and FS surfaces were made concrete enough that the theorem-facing bounds close without in-tree axioms

## Current Theorem-Facing Status

The active theorem stack is checker-green end to end.

- `theorem/MainTheorem.ec` already owns the complete public corollary surface: `qssm_main_theorem` is the exact-zero abstraction theorem, and `qssm_main_theorem_semantic_budget` is the preferred semantic-budget theorem closing at `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic + epsilon_le_semantic`
- `theorem/MainTheoremParameterized.ec` now owns two additional public theorems: `qssm_main_theorem_le_parameterized_budget`, which keeps the canonical/demo MS contribution unchanged and parameterizes only the LE side through `GameLEBridgeParameterized.ec`, and `qssm_main_theorem_parameterized_budget`, which closes the full canonical parameterized route
- `games/GameMSHopCompositionParameterized.ec` now exports `A_G0_to_G1_ms_parameterized_transition_bound`, and its bound is `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized`
- `ms/MSProbabilitySurfaceParameterized.ec` now exports the budgeted landing theorem `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound`; this is a charged bridge, not a zero-cost identification, so public AfterRom remains budget-close to canonical AfterRom rather than zero-equal
- `qssm_main_theorem_semantic_budget_umbrella` and `qssm_main_theorem_nonzero_budget` are the retained umbrella / discoverability aliases, while `qssm_main_theorem_semantic_budget_local_mass` and `qssm_main_theorem_semantic_budget_owned` remain for proof history and bisectability; no separate `Corollaries.ec` file is needed
- `theorem/MainTheorem.ec` keeps `qssm_main_theorem_skeleton` / `qssm_main_theorem` on the current exact-zero MS and LE game-hop chain, while the semantic variants consume `A_G0_to_G1_ms_semantic_transition_bound` plus the semantic LE bridge
- The MS parameterized route now has two layers: an internal staged/public-endpoint lane and a closed canonical route. The staged lane still exists because the lower proof still factors through the public endpoint, but `GameMSHopCompositionParameterized.ec` now re-enters the canonical `Adv_G0_G1_MS` telescope by paying an explicit extra `epsilon_ms_rom_programmability_parameterized` landing charge
- `ms/` closes the MS1, MS2, MS-3a, MS-3b, and MS-3c game-hop surfaces on the current carrier
- `le/` closes the rejection and FS component bounds on the current lower carriers and component budgets
- `games/` packages the MS and LE transition bounds into the final additive theorem path
- `sim/Simulator.ec` closes the public-surface bridge needed for the MS-to-LE handoff

## Parameterized Checkpoint

The live parameterized LE route, the live parameterized MS1 route, and the live parameterized MS2 route are now fully landed and reach the closed canonical parameterized theorem.

- `primitives/ParameterizedBudgetParameters.ec` now carries the active LE rejection parameterized counts `soft=1`, `hard=1`, `invalid=1`, `accept=29`, `failure=3`, `total=32`, so `epsilon_le_rej_parameterized = 3%r / 32%r`.
- The same file now carries the active LE FS parameterized counts `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_le_fs_parameterized = 3%r / 32%r`.
- `le/LERejectionSamplerParameterizedCore.ec` and `le/LERejectionSamplerMassLiveParameterized.ec` own the live parameterized rejection core and mass/sdist closure.
- `le/LEFsProgrammingLiveParameterizedCore.ec` and `le/LEFsProgrammingLiveParameterizedMass.ec` own the live parameterized FS branch/midpoint core and bad-branch mass/sdist closure.
- `le/LEFsProgrammingParameterizedView.ec`, `le/LERejectionParameterized.ec`, `le/LEFsProgrammingParameterized.ec`, and `le/LEStatisticalDistanceParameterized.ec` now route through those live LE midpoints.
- `epsilon_le_parameterized = epsilon_le_rej_parameterized + epsilon_le_fs_parameterized = 6%r / 32%r = 3%r / 16%r`.
- `primitives/ParameterizedBudgetParameters.ec` now also carries the active MS1 profile `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_ms_hash_binding_parameterized = 3%r / 32%r`.
- `ms/source/SourceHashBindingSemanticLiveParameterizedCore.ec` owns the live MS1 coupled-state/public-observable core, and `ms/source/SourceHashBindingSemanticLiveParameterizedMass.ec` owns live MS1 canonical failure and public-divergence upper mass closure.
- `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`, `ms/MSProbabilitySurfaceParameterized.ec`, `games/GameAdvantageParameterized.ec`, `games/GameMSHopTypesParameterized.ec`, and `games/GameMSHopCompositionParameterized.ec` now carry the live MS1 staged/public-endpoint route, so the staged MS1 lane is no longer demo-bound and the public-divergence upper lane closes at `2%r / 32%r = 1%r / 16%r`.
- `primitives/ParameterizedBudgetParameters.ec` now also carries the active MS2 profile `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_ms_rom_programmability_parameterized = 3%r / 32%r`.
- `ms/comparison/ComparisonPayloadSemanticLiveParameterizedCore.ec` owns the live MS2 category/coupled-state/public-AfterRom core, and `ms/comparison/ComparisonPayloadSemanticLiveParameterizedMass.ec` owns live MS2 execution-owned failure and public-divergence/failure mass closure.
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`, `ms/MSProbabilitySurfaceParameterized.ec`, `games/GameAdvantageParameterized.ec`, `games/GameMSHopTypesParameterized.ec`, and `games/GameMSHopCompositionParameterized.ec` now carry the live MS2 staged/public-endpoint transition and budgeted public-to-canonical landing route.
- `BudgetParameters.ec`, `MainTheorem.ec`, `LERealExecution.ec`, `LERejection.ec`, and demo `LEStatisticalDistance.ec` remain unchanged.
- `qssm_main_theorem_parameterized_budget` remains closed with the explicit duplicated MS2 charge, now at active closed form `15%r / 32%r`, and no remaining localized replay seams are expected on the current uniform finite-support / contiguous-layout profile family.

## Budget Models Today

The current budget surface is defined in `primitives/BudgetParameters.ec`.

The exact-zero theorem path uses these values:

- `epsilon_ms_hash_binding = 0%r`
- `epsilon_ms_rom_programmability = 0%r`
- `epsilon_le_rej = 0%r`
- `epsilon_le_fs = 0%r`
- `epsilon_le = epsilon_le_rej + epsilon_le_fs = 0%r`

The semantic owner surface beside that theorem path adds these values:

- `ms_hash_binding_semantic_category_support = [MSHashBindingSemanticClean; MSHashBindingSemanticCollision; MSHashBindingSemanticMalformedBinding; MSHashBindingSemanticTranscriptMismatch]`
- `ms_hash_binding_semantic_category_is_failure category = (category <> MSHashBindingSemanticClean)`
- primitive MS hash-binding owner counts are `ms_hash_binding_clean_slot_count=13`, `ms_hash_binding_collision_slot_count=1`, `ms_hash_binding_malformed_binding_slot_count=1`, `ms_hash_binding_transcript_mismatch_slot_count=1`
- `ms_hash_binding_failure_slot_count = ms_hash_binding_collision_slot_count + ms_hash_binding_malformed_binding_slot_count + ms_hash_binding_transcript_mismatch_slot_count = 3`
- `ms_hash_binding_total_slot_count = ms_hash_binding_clean_slot_count + ms_hash_binding_failure_slot_count = 16`
- `epsilon_ms_hash_binding_semantic = ms_hash_binding_failure_slot_count%r / ms_hash_binding_total_slot_count%r = 3%r / 16%r`
- `primitives/FS.ec` re-exports `epsilon_ms_hash_binding_semantic`, and `ms/MS.ec` now stages the same owner on the MS-facing route via `MS.epsilon_ms_hash_binding_semantic` and `MS.A1_ms_hash_binding_semantic_nonneg`
- `ms/source/SourceHashBindingSemanticSlotMass.ec` now owns `ms_hash_binding_local_failure_mass` for that semantic MS1 owner
- `ms/source/SourceHashBindingSemanticBridge.ec` now consumes that owner to give a source-local execution-owned bridge via `ms_hash_binding_semantic_state_of_category_source`, `ms_hash_binding_semantic_category_condition`, and `A_MS1_hash_binding_execution_owned_semantic_bound`
- `ms/source/SourceHashBindingSemanticBridge.ec` now also proves the bridge-local public-divergence upper mass `ms_hash_binding_local_public_divergence_upper_mass = 1%r / 8%r` together with `ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass`
- `ms/MSProbabilitySurface.ec` now stages that same `1%r / 8%r` fact in `L_ms1_public_after_binding_transition_le_local_public_divergence_upper_mass` and `L_ms1_public_after_binding_compatibility_le_local_public_divergence_upper_mass`, but those lemmas remain lower-surface evidence only and do not replace the theorem-facing `A_MS1_hash_binding_semantic_observable_transition_bound` / `A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound` path
- `ms/MSProbabilitySurface.ec`, `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`, and `games/GameMSHopTransitions.ec` now lift the staged semantic MS1 sibling chain through `A_MS1_hash_binding_semantic_bad_event_bound`, `A_MS1_hash_binding_semantic_game_pr_core_bound`, `A_MS1_hash_binding_semantic_concrete_pair_advantage_bound`, `A_MS1_canonical_hash_binding_semantic_bound`, and `A_MS1_hash_binding_semantic_transition`
- `games/GameMSHopComposition.ec` now also carries the staged sibling `A_G0_to_G1_ms_hash_binding_semantic_transition_bound`, while the existing live semantic theorem `A_G0_to_G1_ms_semantic_transition_bound` and the semantic variants in `theorem/MainTheorem.ec` already consume `epsilon_ms_hash_binding_semantic`; only the exact-zero public route still consumes `epsilon_ms_hash_binding = 0%r`
- `ms/MSProbabilitySurface.ec` now also carries the staged public-endpoint theorems `A_MS2_rom_programming_semantic_public_endpoint_transition_bound`, `A_MS1_to_MS2_semantic_public_endpoint_transition_bound`, `A_MS1_to_MS2_semantic_public_endpoint_visible_flags_bound`, `A_MS1_to_MS2_semantic_public_endpoint_local_visible_flags_bound`, and `A_MS1_to_MS2_semantic_public_endpoint_local_visible_flags_closed_form_bound`, while `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`, and `games/GameMSHopComposition.ec` lift the same segment into the parallel staged route through `Adv_ms_public_endpoint`, staged wrapper lemmas, and staged composition aliases. The visible-flags sibling keeps the MS2 public term on the refined visible divergence mass, the local-visible sibling rewrites the MS1 contribution symbolically through `ms_hash_binding_local_public_divergence_upper_mass`, and the closed-form corollary rewrites only that staged MS1 local term to `1%r / 8%r`. All of these theorems remain staged-only and unused upward: the live route already pays canonical MS1 once through `A_MS1_hash_binding_semantic_transition` and canonical MS2 once through `A_MS2_rom_programming_semantic_transition`, and the staged public-endpoint route also covers that same MS1+MS2 segment, so stacking it on top of the current route would double-count the routed MS segment. Routed theorem surfaces therefore remain unchanged, the exact-zero route remains separate, and the live semantic top stays `3%r / 4%r`. Any future live use must replace the current MS1+MS2 witness behind the unchanged routed theorem names rather than stack on top of them, and the visible-flags / local-visible variants remain staged refinements only.
- May 2026 canonical-terminal resolution: the lower public-to-canonical issue was not solved by proving zero public divergence. The current comparison-local bridge still proves only the nonzero divergence-mass bound `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure`, and there is still no zero-cost `public AfterRom -> canonical AfterRom` landing on the lower surface. What changed is the theorem-facing route: `ms/MSProbabilitySurfaceParameterized.ec` now exports the charged landing theorem `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound`, `games/GameMSHopCompositionParameterized.ec` composes that landing into `A_G0_to_G1_ms_parameterized_transition_bound`, and `theorem/MainTheoremParameterized.ec` pays the resulting duplicated MS2 charge explicitly. The exact-zero route stays unchanged, the live demo semantic top stays `3%r / 4%r`, and any future tightening would need a stronger lower fusion law to remove that extra charge honestly.

- `ms_rom_semantic_category_support = [MSROMSemanticClean; MSROMSemanticQueryCollision; MSROMSemanticProgrammingCollision; MSROMSemanticTranscriptMismatch]`
- `ms_rom_semantic_category_is_failure category = (category <> MSROMSemanticClean)`
- primitive MS ROM owner counts are `ms_rom_clean_slot_count=13`, `ms_rom_query_collision_slot_count=1`, `ms_rom_programming_collision_slot_count=1`, `ms_rom_transcript_mismatch_slot_count=1`
- `ms_rom_failure_slot_count = ms_rom_query_collision_slot_count + ms_rom_programming_collision_slot_count + ms_rom_transcript_mismatch_slot_count = 3`
- `ms_rom_total_slot_count = ms_rom_clean_slot_count + ms_rom_failure_slot_count = 16`
- `epsilon_ms_rom_programmability_semantic = ms_rom_failure_slot_count%r / ms_rom_total_slot_count%r = 3%r / 16%r`
- `primitives/FS.ec` now re-exports `epsilon_ms_rom_programmability_semantic` together with `A2_ms_rom_programmability_semantic_nonneg`
- `ms/comparison/ComparisonPayloadSemanticSlotMass.ec` now owns `ms_rom_local_failure_mass` for that semantic MS2 ROM owner
- `ms/comparison/ComparisonPayloadSemanticBridge.ec` now consumes that owner to give a comparison-local execution-owned bridge surface via `ms_rom_semantic_state_of_category_execution_seed`, `ms_rom_semantic_category_condition`, and `A_MS2_rom_programming_execution_owned_semantic_bound`
- `ms/MSProbabilitySurface.ec` now also carries the semantic-public endpoint `d_ms_after_rom_public_semantic_observable_v2`, the local replacement law `L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure`, the refined helper-side bad predicate `ms_rom_public_observable_divergence_condition`, and the retargeted local semantic bound `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure`, while `A_MS2_rom_programming_semantic_transition_bound` still depends directly on `A_MS2_rom_programming_execution_owned_semantic_bound` and the exact-zero `A_MS2_rom_programming_transition_bound` remains unchanged
- `games/GameAdvantage.ec`, `games/GameMSHopTypes.ec`, `games/GameMSHopTransitions.ec`, and `games/GameMSHopComposition.ec` still lift the unchanged semantic sibling chain through `A_G0_to_G1_ms_semantic_transition_bound`
- the semantic MainTheorem variants now consume that sibling chain through `A_G0_to_G1_ms_semantic_transition_bound`, adding `epsilon_ms_rom_programmability_semantic = 3%r / 16%r`, while the exact-zero public route still consumes `epsilon_ms_rom_programmability = 0%r`

- `le_rejection_semantic_ticket_category_support = [soft_repair; hard_repair; invalid; accept]`
- `le_rejection_semantic_ticket_category_is_failure category = (category <> accept)`
- primitive rejection owner counts are `le_rej_soft_repair_slot_count=1`, `le_rej_hard_repair_slot_count=1`, `le_rej_invalid_slot_count=1`, `le_rej_accept_slot_count=13`
- `le_rej_failure_slot_count = le_rej_soft_repair_slot_count + le_rej_hard_repair_slot_count + le_rej_invalid_slot_count = 3`
- `le_rej_total_slot_count = le_rej_accept_slot_count + le_rej_failure_slot_count = 16`
- `d_le_rejection_semantic_branch_slot_choice = duniform (range 0 le_rejection_semantic_total_slot_count)`
- `d_le_rejection_semantic_branch_choice = dmap d_le_rejection_semantic_branch_slot_choice le_rejection_semantic_reject_branch_slot`
- `epsilon_le_rej_semantic = mu1 d_le_rejection_semantic_branch_choice true = le_rej_failure_slot_count%r / le_rej_total_slot_count%r = 3%r / 16%r`
- `le_fs_semantic_branch_category_support = [clean; query_collision; programming_collision; transcript_mismatch]`
- `le_fs_semantic_branch_category_is_failure category = (category <> clean)`
- primitive FS owner counts are `le_fs_clean_slot_count=13`, `le_fs_query_collision_slot_count=1`, `le_fs_programming_collision_slot_count=1`, `le_fs_transcript_mismatch_slot_count=1`
- `le_fs_failure_slot_count = le_fs_query_collision_slot_count + le_fs_programming_collision_slot_count + le_fs_transcript_mismatch_slot_count = 3`
- `le_fs_total_slot_count = le_fs_clean_slot_count + le_fs_failure_slot_count = 16`
- exact FS interpretation ops are `d_le_fs_shadow_category_choice`, `le_fs_shadow_state_of_category_observable`, `le_fs_shadow_clean_condition`, `le_fs_shadow_query_collision_condition`, `le_fs_shadow_programming_collision_condition`, and `le_fs_shadow_transcript_mismatch_condition`
- exact FS category witness lemmas are `le_fs_shadow_clean_condition_clean_categoryE`, `le_fs_shadow_query_collision_condition_query_collision_categoryE`, `le_fs_shadow_programming_collision_condition_programming_collision_categoryE`, `le_fs_shadow_transcript_mismatch_condition_transcript_mismatch_categoryE`, and `le_fs_shadow_semantic_category_condition_stateE`
- `LEFsProgrammingSurface.ec` now interprets the primitive FS categories on a category-coupled shadow state: `clean` is the no-failure/programmed-view branch, `query_collision` is bad-branch query-row alignment, `programming_collision` is bad-branch programmed-response digest/log alignment, and `transcript_mismatch` is bad-branch visible-shell agreement with a cleared semantic bad flag
- `total_slot_count = le_fs_total_slot_count = 16`
- `bad_slot_count = le_fs_failure_slot_count = 3`
- `d_le_fs_semantic_branch_slot_choice = duniform (range 0 total_slot_count)`
- `d_le_fs_semantic_branch_choice = dmap d_le_fs_semantic_branch_category_choice le_fs_semantic_branch_category_is_failure`
- `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true = le_fs_failure_slot_count%r / le_fs_total_slot_count%r = 3%r / 16%r`
- `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic = 3%r / 8%r`

The current theorem-facing results therefore split into two checked modes: an exact-zero bound on the active abstraction theorem path, and a separate semantic-budget theorem path that now packages the present semantic MS1, semantic MS ROM, semantic rejection, and semantic FS modeling through `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic + epsilon_le_semantic`. The live semantic theorem path now consumes `epsilon_ms_hash_binding_semantic = 3%r / 16%r` through the retargeted `A_G0_to_G1_ms_semantic_transition_bound` and the semantic MainTheorem variants, while the exact-zero public route still consumes `epsilon_ms_hash_binding = 0%r`. The newer MS1 public-divergence upper mass `1%r / 8%r` is intentionally staged-only evidence below that theorem-facing route: it is available in the bridge and local MS probability surface lemmas, but it does not replace the audited `3%r / 16%r` owner path or alter any public theorem statement. The semantic rejection component is now execution-owned below the theorem-facing budget surface, and its probability law remains primitive-owned in `BudgetParameters.ec` through the named count constants `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`, `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`, `le_rej_failure_slot_count`, and `le_rej_total_slot_count`. The current rejection demo instance is now `1,1,1,13`, so `epsilon_le_rej_semantic = 3%r / 16%r`. The semantic FS component is likewise primitive-owned in `BudgetParameters.ec`, and it now has execution-owned meaning in `LEFsProgrammingSurface.ec` rather than only a toy two-slot surrogate view: `clean` is the no-failure/programmed-view branch, while `query_collision`, `programming_collision`, and `transcript_mismatch` each witness a concrete bad-branch condition on the lower shadow state. The local FS bridge still proves equality `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic`, and theorem-facing wrappers then consume the corresponding `<=` bound. The present semantic umbrella therefore evaluates to `3%r / 16%r + 3%r / 16%r + 3%r / 8%r = 3%r / 4%r`; that statement should not be confused with a final realistic cryptographic reduction for the deployed implementation.

The current semantic FS slot counts are therefore frozen as concrete demo/proof parameters in `primitives/BudgetParameters.ec`, but they now live under stable owner names rather than as anonymous fixed masses. They are not yet sourced from a protocol-parameter bundle, and any future extraction to `primitives/ProtocolParameters.ec` is deferred until there is a real shared protocol parameter surface to centralize.

## What Is Proved on the Live Path

- MS1 hash-binding closes through the current lower probability surface and exact stage equalities.
- The exact-zero MS2 theorem still closes through the current lower stage equality between the AfterBinding and AfterRom observable laws, while the semantic MS2 lane now also carries a separate non-identity AfterBinding-to-semantic-public-AfterRom bound driven by `ms_rom_public_observable_divergence_condition` and bounded by `ms_rom_execution_owned_semantic_failure_probability`.
- LE rejection closes on two lower lanes: the active exact-zero rejection lane still collapses to zero on the theorem-facing carrier, while the semantic rejection lane is now execution-owned below the theorem surface and still closes to the owned failure quantity `epsilon_le_rej_semantic = 3%r / 16%r`.
- LE FS closes through the semantic shadow FS lane, whose current failure probability also collapses to zero on the active carrier.
- `LEStatisticalDistance.ec` consumes the rejection and FS component endpoints additively through `epsilon_le = epsilon_le_rej + epsilon_le_fs`.
- `MainTheorem.ec` packages the resulting MS and LE bounds into the final theorem-facing statement, and its semantic theorem path now uses `A_G0_to_G1_ms_semantic_transition_bound` together with local rejection failure plus local FS bad-branch mass at the comparison level, the owned component sum `epsilon_le_rej_semantic + epsilon_le_fs_semantic`, and the umbrella budget `epsilon_le_semantic`.

## What Is Not Modeled Yet

The following items remain outside the current exact-zero theorem path:

- tightening or further routing the current semantic-public MS2 AfterRom surrogate now that the lower public carrier retarget and public-divergence refinement are checker-green below the theorem surface
- whether the staged sibling `A_G0_to_G1_ms_hash_binding_semantic_transition_bound` should remain as a parallel bisectable theorem now that the live semantic top-level route also consumes `epsilon_ms_hash_binding_semantic`
- a true category-carrying LE rejection material split below the current shared boolean reject carrier for `soft_repair`, `hard_repair`, and `invalid`
- production-profile-independent MS1/MS2 local comparison seams beyond the current localized bridges
- a nonzero end-to-end quantitative budget connected to realistic lower assumptions
- a machine-checked refinement link from the EasyCrypt model to the Rust implementation

## Current Next Target

The localized replay campaign for the current uniform `3%r / 32%r` profile family is now complete. The live parameterized LE route is landed and checker-green through `LERejectionSamplerParameterizedCore.ec`, `LERejectionSamplerMassLiveParameterized.ec`, `LEFsProgrammingLiveParameterizedCore.ec`, `LEFsProgrammingLiveParameterizedMass.ec`, `LEFsProgrammingParameterizedView.ec`, `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, and `LEStatisticalDistanceParameterized.ec`, with both `epsilon_le_rej_parameterized` and `epsilon_le_fs_parameterized` at `3%r / 32%r`, so `epsilon_le_parameterized = 3%r / 16%r` reaches `qssm_main_theorem_parameterized_budget`. The live parameterized MS1 route is also landed and checker-green through `SourceHashBindingSemanticLiveParameterizedCore.ec`, `SourceHashBindingSemanticLiveParameterizedMass.ec`, `SourceHashBindingSemanticBridgeParameterized.ec`, `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec`, with the canonical failure lane at `epsilon_ms_hash_binding_parameterized = 3%r / 32%r` and the staged public-divergence upper lane at `2%r / 32%r = 1%r / 16%r`. The live parameterized MS2 route is now also checker-green through `ComparisonPayloadSemanticLiveParameterizedCore.ec`, `ComparisonPayloadSemanticLiveParameterizedMass.ec`, `ComparisonPayloadSemanticBridgeParameterized.ec`, `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec`, with `epsilon_ms_rom_programmability_parameterized = 3%r / 32%r` used on both the staged public-endpoint transition and the budgeted public-to-canonical landing. The demo semantic route and exact-zero route remain unchanged, the duplicated MS2 charge remains explicit, and no remaining localized replay seams are expected on the current profile family.

The execution-owned semantic rejection-to-FS handoff is now landed and checker-green. `LERealExecution.ec` owns the semantic rejection support/material, `LERejectionSampler.d_le_semantic_post_rejection_view` is the semantic midpoint, `LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view` feeds that midpoint into the semantic FS lane, and `games/GameLEBridge.ec` now packages the resulting semantic projected-simulation advantage without changing the exact-zero theorem path.

The richer execution-owned semantic rejection repair is now also landed and checker-green. `LERealExecution.ec` now carries a semantic rejection decision/ticket together with a repaired reject-branch observable whose hidden query material is brought back into alignment with the repaired visible challenge/programmed-query digests, and the downstream semantic sampler, FS surface, and bridge proofs have all been replayed against that richer surface.

The semantic rejection budget grounding is now also landed and checker-green. `BudgetParameters.epsilon_le_rej_semantic` is now a primitive multi-category ticket-failure probability: `soft_repair`, `hard_repair`, and `invalid` are failure categories, `accept` is the only nonfailure category, and the current rejection count owners are `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`, `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`, `le_rej_failure_slot_count`, and `le_rej_total_slot_count`. The current demo instance is now `1,1,1,13`, so the budget closes to `3%r / 16%r`. `LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability` proves that the concrete execution-owned ticket sampler projects to that primitive law, and `LERejectionSampler.le_rejection_shadow_semantic_failure_probability` is now proved equal to that ticket-failure quantity.

The current milestone decision is to keep that four-way budget law while also keeping the lower execution/sampler material carrier on its current shared reject-branch shape. `LERealExecution.ec` and `LERejectionSampler.ec` now prove category-to-branch consequences, but `soft_repair`, `hard_repair`, and `invalid` are not materially distinguished yet: they all project to the same failure-side reject/repair/material behavior, while `accept` is the only nonfailure branch. This is acceptable on the current theorem path because the live consumers only use failure-vs-accept, repair/no-repair, and aligned reject-branch material facts. No budgets, theorem names, exact-zero route, or semantic top changed in this step; the semantic top remains `3%r / 4%r`.

The next exact local target is therefore no longer the rejection-owner handoff, the richer repair plumbing, the ticket-failure grounding step itself, or the primitive category split. Semantic count ownership remains intentionally frozen: the current rejection and FS demo/proof counts stay in `primitives/BudgetParameters.ec`, and any `primitives/ProtocolParameters.ec` move remains deferred until there is a real shared protocol-owned source worth centralizing. The current milestone is satisfied by the shared reject-branch carrier. If future realism work truly needs `soft_repair`, `hard_repair`, and `invalid` to have distinct material consequences, that should be done as an additive category-carrying constructor/ticket layer in `LERealExecution.ec`, then replayed through the sampler below the theorem-facing wrappers rather than by changing the public theorem API or budget owners:

- keep `qssm_main_theorem` as the exact-zero abstraction theorem and `qssm_main_theorem_semantic_budget` as the preferred nonzero citation target
- keep the axiom count at `0`
- keep the current exact-zero theorem path unchanged while any future material split remains strictly below the theorem-facing rejection wrappers
- defer any future `primitives/ProtocolParameters.ec` move until there is a real shared parameter source worth centralizing

This is the best current stopping point because the semantic rejection owner, semantic post-rejection midpoint, repaired rejection ticket/observable, primitive category law, ticket-failure bridge, semantic FS pre-image, bridge packaging, semantic umbrella plumbing, live MS1 route, and live MS2 route are now all installed and checker-green. The next design target, if parameterized work resumes here, is a profile-generalization audit or release packaging rather than another localized replay slice.

The MS2 visible/silent micro-layer is now intentionally stopped and checkpointed. The bridge-local execution-owned decomposition, common-equality normalization, normalized bundle / wrapper packaging, projection helpers, and round-trip helper are in place below routing, and no further normalized-wrapper micro-helpers are planned on the live route. The next work item is roadmap triage rather than more MS2 bridge-local proof churn.

For the longer-lived trail that led to the current state, see [PROOF_HISTORY.md](PROOF_HISTORY.md).