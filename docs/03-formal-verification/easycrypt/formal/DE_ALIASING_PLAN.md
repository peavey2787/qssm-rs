# De-Aliasing Plan

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document audits the current parameterized proof lane for production-count substitution readiness.

Its purpose is to isolate every alias-dependent bridge, identify the first breakpoints once parameterized counts diverge from the demo counts, and record which higher layers should survive unchanged after the lower replacements land.

This is a docs-only roadmap.

- It does not change any EasyCrypt proof file.
- It does not mutate `ParameterizedBudgetParameters.ec`.
- It does not mutate `BudgetParameters.ec`.
- It does not mutate theorem statements.
- It does not change the explicit duplicated MS2 charge in the current canonical parameterized theorem.

## Current Theorem Architecture

The current parameterized theorem stack is organized in five layers.

### Owner layer

This layer owns parameterized counts, derived epsilons, and local mass identities.

- `primitives/ParameterizedBudgetParameters.ec`
- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
- `le/LERejectionSamplerMassParameterized.ec`
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`

### Bridge layer

This layer is where demo semantic facts are currently re-exported to the parameterized lane.

- `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `le/LERejectionParameterized.ec`
- `le/LEFsProgrammingParameterized.ec`
- `ms/MSProbabilitySurfaceParameterized.ec`

### Wrapper layer

This layer packages lower bounds into reusable parameterized MS and LE wrappers.

- `le/LEStatisticalDistanceParameterized.ec`
- `le/LEHVZKParameterized.ec`
- `games/GameLEBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopTypesParameterized.ec`

### Game layer

This layer re-enters the canonical game hop with the now-explicit duplicated MS2 landing charge.

- `games/GameMSHopCompositionParameterized.ec`

### Top-level layer

This layer exposes the public parameterized theorem surface.

- `theorem/MainTheoremParameterized.ec`

## Theorem Classes

This audit uses three classes.

- `genuinely parameterized`: the theorem is phrased over parameterized operators and should remain provable without semantic-demo equalities once the parameterized counts diverge.
- `alias-dependent`: the theorem currently closes only because it directly proves or rewrites an equality between demo semantic quantities and parameterized quantities.
- `mixed`: the theorem does not directly prove the alias equality itself, but it still depends on one or more alias-dependent lower theorems and therefore is not yet production-ready by itself.

## Fully Production-Ready Components

These components are the structurally durable parts of the parameterized lane. They are the pieces that should remain unchanged, or need only trivial replay, once real production counts replace the current demo aliases.

### Parameterized owner arithmetic

`primitives/ParameterizedBudgetParameters.ec` is structurally ready even though its current count operators still alias `BudgetParameters`.

- Component-sum lemmas such as `ms1_param_failure_count_component_sum` and `ms2_param_failure_count_component_sum` are genuine arithmetic.
- Nonnegativity and positivity lemmas such as `epsilon_ms_hash_binding_parameterized_nonneg`, `epsilon_ms_rom_programmability_parameterized_nonneg`, `epsilon_le_rej_parameterized_nonneg`, `epsilon_le_fs_parameterized_nonneg`, and `epsilon_le_parameterized_nonneg` are genuine arithmetic over the parameterized operators.
- The owner-layer additive structure `epsilon_le_parameterized = epsilon_le_rej_parameterized + epsilon_le_fs_parameterized` is already the right long-term architecture.

Classification: `mixed` at file level because the current count operators still alias demo counts, but the arithmetic lemmas themselves are structurally production-ready.

### Parameterized helper lemmas and local mass theorems

The local mass files are mostly already expressed over parameterized operators and should survive a future count substitution unchanged.

- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`
  - `ms_hash_binding_semantic_failure_choice_mass_true_parameterized`
  - `ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_parameterized`
  - `ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_parameterized`
  - `ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized`
  - `ms_hash_binding_local_public_divergence_upper_mass_le_epsilon_ms_hash_binding_parameterized`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
  - `ms_rom_semantic_failure_choice_mass_true_parameterized`
  - `ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_parameterized`
  - `ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_parameterized`
- `le/LERejectionSamplerMassParameterized.ec`
  - `le_rejection_shadow_semantic_ticket_failure_probability_parameterized_eq_epsilon_le_rej_parameterized`
  - `le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability_parameterized`
  - `le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_parameterized`
  - `le_rejection_shadow_semantic_failure_probability_le_epsilon_le_rej_parameterized`
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`
  - `le_fs_failure_probability_eq_epsilon_le_fs_parameterized`
  - `le_fs_failure_probability_le_epsilon_le_fs_parameterized`

These results are still fed by the current aliasing owner definitions, but they do not rely on semantic-demo equality lemmas. Once the parameterized counts change, these files should continue to prove the same theorems over the new parameterized operators.

Classification: mostly `genuinely parameterized` at theorem level.

### Upper wrapper structure

The upper wrapper architecture is already the right one and appears reusable once the bridge layer is repaired.

- `le/LEStatisticalDistanceParameterized.ec`
- `le/LEHVZKParameterized.ec`
- `games/GameLEBridgeParameterized.ec`
- most of `games/GameAdvantageParameterized.ec`
- most of `games/GameMSHopCompositionParameterized.ec`

These files mostly add bounds, perform triangle-inequality composition, or forward lower theorems. Their current weakness is lower-input dependence, not architectural shape.

Classification: generally `mixed`.

### LE combined wrapper chain

The LE chain appears especially reusable once lower LE bridges are de-aliased.

- `A_LE_semantic_combined_hiding_bounds_sdist_parameterized_budget`
- `A_LE_semantic_view_advantage_bound_from_parameterized_budget`
- `A_LE_HVZK_semantic_parameterized_budget_transition_bound`
- `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound`

These theorems combine already-packaged LE components and should survive if the lower rejection and FS bridges keep their current theorem names and inequality directions.

Classification: `mixed`, but structurally stable.

### Canonical top-level theorem architecture

`theorem/MainTheoremParameterized.ec` appears structurally stable.

- `qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate theorem.
- `qssm_main_theorem_parameterized_budget` already exposes the intended long-term architecture for the full parameterized route.
- The canonical top-level bound remains explicit:

```text
epsilon_ms_hash_binding_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_le_parameterized
```

The theorem architecture should remain untouched during production-count substitution.

Classification: `mixed`, but structurally stable.

## Structurally De-Aliased Upper Paths

The recent LE rejection, LE FS, MS1, and MS2 bridge pilots pushed the broad semantic-to-parameterized epsilon rewrites downward into localized comparison theorems.

The following theorem paths should now be treated as structurally de-aliased upper consumers.

- `A_LE_rejection_sampler_semantic_sdist_parameterized_bound` now forwards the semantic experiment theorem through `A_LE_rejection_shadow_semantic_failure_probability_le_parameterized_budget`; the remaining count-alias sensitivity is localized below it at `le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget`.
- `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget` now forwards the semantic bad-branch experiment theorem through `le_fs_shadow_local_bad_branch_mass_le_parameterized_budget`; the remaining count-alias sensitivity is localized below it at that bad-branch comparison theorem.
- `A_MS1_hash_binding_execution_owned_parameterized_bound` now routes through `ms_hash_binding_local_failure_mass_le_parameterized_budget`, not the broad semantic-to-parameterized epsilon equality.
- `ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_parameterized` now routes through `ms_hash_binding_local_public_divergence_upper_mass_le_parameterized_upper_mass`; the remaining count-alias sensitivity is localized at the live upper-mass comparison itself.
- `A_MS2_rom_programming_execution_owned_parameterized_bound` now routes through `ms_rom_local_failure_mass_le_parameterized_budget`, not the broad semantic-to-parameterized epsilon equality.
- `A_MS2_rom_programming_parameterized_public_endpoint_transition_bound` now composes `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure` with `A_MS2_rom_programming_execution_owned_parameterized_bound`; it no longer rewrites the broad MS2 semantic/parameterized epsilon equality directly.
- `A_MS_public_endpoint_parameterized_transition_bound` now composes the repaired MS1/MS2 public-endpoint theorems instead of directly rewriting broad semantic/parameterized equalities.

Classification: `mixed`, but structurally de-aliased above the remaining localized comparison seams.

## Alias-Dependent Components

The following theorems are the compatibility-only equalities and exact-equality companions that still close only because the current parameterized counts alias the demo counts.

The structurally de-aliased upper theorem paths listed above are no longer direct members of this class.

| Theorem | Current alias dependency | Demo theorem reused | Future replacement obligation | Replay complexity |
|---|---|---|---|---|
| `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` | direct equality between `BudgetParameters.epsilon_ms_hash_binding_semantic` and `ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized` by expanding both closed forms | none; closes by algebra over aliased counts | keep only as a compatibility shim, or retire it from the active route once production counts diverge | low |
| `ms_hash_binding_local_public_divergence_upper_mass_eq_parameterized` | rewrites the demo upper-mass closed form to the parameterized one because counts coincide | `ms_hash_binding_local_public_divergence_upper_mass` owner from the demo lane | keep only as a compatibility equality; the active route should continue to consume the `<=` comparison theorem instead | medium |
| `ms_hash_binding_execution_owned_semantic_failure_probability_eq_epsilon_ms_hash_binding_parameterized` | chains `ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass`, `ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic`, and `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` | `ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass` | keep only as a compatibility exact-equality companion; the active route should continue to use `A_MS1_hash_binding_execution_owned_parameterized_bound` | medium |
| `epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized` | direct equality between demo semantic MS2 epsilon and parameterized MS2 epsilon by expanding aliased counts | none; closes by algebra over aliased counts | keep only as a compatibility shim, or retire it from the active route once production counts diverge | low |
| `ms_rom_local_failure_mass_eq_parameterized` | rewrites the demo local failure mass to the parameterized one through the alias equality | `ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic` | keep only as a compatibility equality; the active route should continue to consume `ms_rom_local_failure_mass_le_parameterized_budget` | medium |
| `ms_rom_execution_owned_semantic_failure_probability_eq_epsilon_ms_rom_programmability_parameterized` | chains `ms_rom_execution_owned_semantic_failure_probability_eq_local_mass`, `ms_rom_local_failure_mass_eq_parameterized`, and the semantic-to-parameterized equality | `ms_rom_execution_owned_semantic_failure_probability_eq_local_mass` | keep only as a compatibility exact-equality companion; the active route should continue to use `A_MS2_rom_programming_execution_owned_parameterized_bound` | medium |
| `epsilon_le_rej_semantic_eq_epsilon_le_rej_parameterized` | direct equality between demo semantic rejection epsilon and parameterized rejection epsilon | none; closes by algebra over aliased counts | keep only as a compatibility shim, or retire it from the active route once production counts diverge | low |
| `le_rejection_shadow_semantic_failure_probability_eq_parameterized` | rewrites the demo semantic rejection failure probability to the parameterized one through the compatibility equality above | `le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic` | keep only as a compatibility exact-equality companion; the active route should continue to use the direct ticket-failure comparison theorem | medium |
| `epsilon_le_fs_semantic_eq_epsilon_le_fs_parameterized` | direct equality between demo semantic FS epsilon and parameterized FS epsilon | none; closes by algebra over aliased counts | keep only as a compatibility shim, or retire it from the active route once production counts diverge | low |

## Remaining Localized Count-Alias-Sensitive Seams

The following theorems are now the real production-count substitution boundary.

| Theorem | Live/demo quantity compared | Parameterized target | Replay class | Upward blast radius |
|---|---|---|---|---|
| `le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget` | `le_rejection_shadow_semantic_ticket_failure_probability x s` | `ParameterizedBudgetParameters.epsilon_le_rej_parameterized` | arithmetic-dominated | LE rejection wrapper chain only; no MS or canonical game-hop replay should be needed if the theorem name and inequality direction stay fixed |
| `le_fs_shadow_local_bad_branch_mass_le_parameterized_budget` | `LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass` | `ParameterizedBudgetParameters.epsilon_le_fs_parameterized` | local semantic replay | LE FS wrapper chain only; still below `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget` |
| `ms_hash_binding_local_failure_mass_le_parameterized_budget` | `ms_hash_binding_local_failure_mass` | `ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized` | local semantic replay | feeds the MS1 execution-owned bridge and the MS1 public-endpoint wrapper path, but should not force canonical landing replay if the theorem name and inequality direction stay fixed |
| `ms_hash_binding_local_public_divergence_upper_mass_le_parameterized_upper_mass` | `ms_hash_binding_local_public_divergence_upper_mass` | `ms_hash_binding_local_public_divergence_upper_mass_parameterized` | public-endpoint replay | feeds only the MS1 public-observable divergence upper theorem and then the public-endpoint MS wrapper path; the canonical MS landing route stays untouched |
| `ms_rom_local_failure_mass_le_parameterized_budget` | `ms_rom_local_failure_mass` | `ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized` | canonical-sensitive replay | feeds the MS2 execution-owned bridge, the MS2 public-endpoint theorem, the public-to-canonical landing theorem, and the explicit duplicated-charge canonical MS route |

## Mixed Components That Should Become Reusable Once Lower Replacements Land

These components are not production-ready today, but they mostly forward lower theorems and should remain unchanged if the lower replacement theorems keep their current names and inequality directions.

### LE wrapper chain

- `A_LE_rejection_semantic_contributes_to_sdist_parameterized_budget`
- `A_LE_fs_semantic_contributes_to_sdist_parameterized_budget`
- `A_LE_semantic_combined_hiding_bounds_sdist_parameterized_budget`
- `A_LE_semantic_view_advantage_bound_from_parameterized_budget`
- `A_LE_HVZK_semantic_parameterized_budget_transition_bound`
- `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound`

Expected reuse after lower replacements: unchanged.

### MS wrapper chain above repaired bridges

- `A_MS1_hash_binding_parameterized_game_advantage_bound`
- `A_MS2_rom_programming_parameterized_game_advantage_bound`
- `A_MS_public_endpoint_parameterized_game_advantage_bound`
- `A_MS_public_after_rom_to_canonical_after_rom_parameterized_bound`
- `A_MS_public_endpoint_to_canonical_parameterized_game_bound`
- `A_MS2_canonical_rom_programming_parameterized_bound`
- `A_G0_to_G1_ms_parameterized_transition_bound`
- `qssm_main_theorem_parameterized_budget`

Expected reuse after lower replacements: mostly unchanged, except for any local replay needed if the MS1 canonical or MS2 canonical theorem names change.

## First True Production-Substitution Breakpoints

When the parameterized counts diverge from the current demo counts, the first actual breakpoints are now the five localized comparison seams above, not the upper theorem routes above them.

### Breakpoint 1: LE rejection ticket-failure comparison

Primary file: `le/LERejectionParameterized.ec`

Current break cause:

- `le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget`

Smallest replacement theorem needed:

- reprove `le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget` against genuinely independent `le_rej_param_*` counts

Practical note:

This is the cheapest honest first slice. The LE theorem names above it should remain unchanged if the theorem name and inequality direction are preserved.

### Breakpoint 2: LE FS bad-branch comparison

Primary file: `le/LEFsProgrammingParameterized.ec`

Current break cause:

- `le_fs_shadow_local_bad_branch_mass_le_parameterized_budget`

Smallest replacement theorem needed:

- reprove `le_fs_shadow_local_bad_branch_mass_le_parameterized_budget` against genuinely independent `le_fs_param_*` counts

Practical note:

This remains a local semantic replay point on the LE side, but it is more branch-sensitive than the rejection seam.

### Breakpoint 3: MS1 local failure comparison

Primary file: `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`

Current break cause:

- `ms_hash_binding_local_failure_mass_le_parameterized_budget`

Smallest replacement theorem needed:

- reprove `ms_hash_binding_local_failure_mass_le_parameterized_budget` against genuinely independent `ms1_param_*` counts

Practical note:

The execution-owned and most public-endpoint theorem names above it should remain unchanged if this theorem name and inequality direction are preserved.

### Breakpoint 4: MS1 public-divergence upper comparison

Primary file: `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`

Current break cause:

- `ms_hash_binding_local_public_divergence_upper_mass_le_parameterized_upper_mass`

Smallest replacement theorem needed:

- reprove `ms_hash_binding_local_public_divergence_upper_mass_le_parameterized_upper_mass` against a genuinely independent parameterized upper mass

Practical note:

This is the only remaining localized seam whose natural replay class is public-endpoint-sensitive rather than a pure local-failure comparison.

### Breakpoint 5: MS2 local failure comparison

Primary file: `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`

Current break cause:

- `ms_rom_local_failure_mass_le_parameterized_budget`

Smallest replacement theorem needed:

- reprove `ms_rom_local_failure_mass_le_parameterized_budget` against genuinely independent `ms2_param_*` counts

Practical note:

This remains the most globally visible localized seam because the MS2 execution-owned bridge, the public-endpoint MS2 theorem, and the public-to-canonical landing theorem all consume it.

## Recommended Production-Substitution Order

The recommended replay order is:

1. replace exactly one parameterized owner subfamily while preserving the current parameterized operator names and arithmetic structure
2. replay the matching localized comparison seam for that owner subfamily
3. verify that the upper wrappers above that seam survive unchanged
4. start with the LE rejection ticket-failure comparison
5. then replay the LE FS bad-branch comparison
6. then replay the MS1 local failure comparison
7. then replay the MS1 public-divergence upper comparison
8. finally replay the MS2 local failure comparison
9. rerun the checker and the zero-axiom / zero-admit validation
10. only after the proof route is stable again, revisit readability or refactor work

Reason for this order:

- the first honest pilot should change only one owner subfamily so profile selection and proof replay stay coupled locally
- the LE route is more locally contained and should validate the substitution process before touching the canonical MS path
- the MS1 public-divergence upper comparison is a separate public-endpoint-sensitive replay surface and should not be conflated with the MS1 local failure replay
- the MS2 local failure comparison is the most globally visible MS dependency because it feeds both the public-endpoint route and the canonical landing
- delaying readability work avoids mixing semantic substitutions with naming churn

## Structural Invariants That Must Remain Frozen

The following invariants must stay unchanged during de-aliasing work.

- `BudgetParameters.ec` unchanged
- `MainTheorem.ec` unchanged
- exact-zero route unchanged
- demo semantic route unchanged
- no hiding of the duplicated MS2 charge
- no false zero-landing claims
- no theorem claim that public AfterRom equals canonical AfterRom
- no theorem claim that `sdist(public AfterRom, canonical AfterRom) = 0`

## Optional Quantitative Prep

No production counts are chosen here, but the following symbolic placeholders are the right planning surface for later substitution work.

| Planning target | Symbolic placeholder | Constraint shape |
|---|---|---|
| target security level budget | `epsilon_top_target` | `epsilon_MS1 + 2 * epsilon_MS2 + epsilon_LE <= epsilon_top_target` |
| target LE semantic budget | `epsilon_LE_target` | `epsilon_LE_rej + epsilon_LE_fs <= epsilon_LE_target` |
| acceptable MS2 landing penalty | `epsilon_MS2_landing_target` | `epsilon_MS2_landing <= epsilon_MS2_landing_target` |

These are planning variables only. They are not proof constants and are not yet production-selected values.

## Optional Future Cleanup Candidates

These are intentionally deferred until after production-count substitution succeeds.

- naming cleanup for the parameterized bridge theorems
- MS2 readability cleanup in `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, and `GameMSHopCompositionParameterized.ec`
- factoring the second MS2 charge into a named landing term if that can be done without hiding the duplicated charge
- theorem inventory tooling for parameterized versus demo routes
- import-graph tooling for the EasyCrypt proof tree

## Recommendations

### First actual production-substitution target

Start with the LE rejection ticket-failure comparison.

Reason:

- it is the smallest localized comparison seam conceptually
- the expected proof touches are `primitives/ParameterizedBudgetParameters.ec` and `le/LERejectionParameterized.ec`
- its upper wrapper chain appears the most reusable unchanged
- it validates the substitution workflow before touching the more expensive MS2 canonical landing path
- `formal/PARAMETER_PROFILES.md` can be updated afterward once the first real profile choice is locked

### Most expensive replay points

The likely highest-cost remaining seam and theorem replay points are:

- `ms_rom_local_failure_mass_le_parameterized_budget`
- `A_MS2_rom_programming_parameterized_canonical_game_pr_core_bound`
- `A_G0_to_G1_ms_parameterized_transition_bound`
- `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget`

Among these, `ms_rom_local_failure_mass_le_parameterized_budget` is the hardest remaining localized seam, and the MS2 canonical game-pr core theorem remains the most architecture-sensitive theorem above it because it is where the duplicate MS2 charge becomes explicit at the canonical game layer.

### Upper-chain stability assessment

Current assessment:

- the LE upper wrapper chain is now structurally de-aliased above the localized rejection and FS comparison seams
- the MS execution-owned and public-endpoint wrapper chain is now structurally de-aliased above the localized MS1 and MS2 comparison seams
- `MainTheoremParameterized.ec` appears structurally stable
- the duplicate MS2 charge appears architecturally unavoidable on the current route unless a future direct canonical landing theorem removes it honestly
