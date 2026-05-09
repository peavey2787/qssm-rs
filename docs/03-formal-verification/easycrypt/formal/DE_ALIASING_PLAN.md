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

## Alias-Dependent Components

The following theorems are the concrete places where the current parameterized lane still depends on demo-count aliasing.

| Theorem | Current alias dependency | Demo theorem reused | Future replacement obligation | Replay complexity |
|---|---|---|---|---|
| `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` | direct equality between `BudgetParameters.epsilon_ms_hash_binding_semantic` and `ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized` by expanding both closed forms | none; closes by algebra over aliased counts | replace with a production-count bridge from demo semantic MS1 failure quantity to the new parameterized owner, likely an inequality or direct parameterized execution-owned theorem | low |
| `ms_hash_binding_local_public_divergence_upper_mass_eq_parameterized` | rewrites demo upper-mass closed form to the parameterized one because counts coincide | `ms_hash_binding_local_public_divergence_upper_mass` owner from the demo lane | replace with a direct parameterized public-divergence upper-mass theorem that no longer relies on demo equality | medium |
| `ms_hash_binding_execution_owned_semantic_failure_probability_eq_epsilon_ms_hash_binding_parameterized` | chains `ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass`, `ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic`, and `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` | `ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass` | replace with a direct production-count execution-owned MS1 bridge, keeping the public theorem name `A_MS1_hash_binding_execution_owned_parameterized_bound` above it | medium |
| `A_MS1_hash_binding_execution_owned_parameterized_bound` | becomes true only because the preceding equality theorem rewrites the demo failure probability to the parameterized epsilon | none beyond the equality chain above | reprove directly from the new execution-owned MS1 bridge | medium |
| `epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized` | direct equality between demo semantic MS2 epsilon and parameterized MS2 epsilon by expanding aliased counts | none; closes by algebra over aliased counts | replace with a production-count bridge from demo semantic MS2 failure quantity to the new parameterized owner, likely an inequality or direct parameterized execution-owned theorem | low |
| `ms_rom_local_failure_mass_eq_parameterized` | rewrites the demo local failure mass to the parameterized one through the alias equality | `ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic` | replace with a direct parameterized MS2 local-failure theorem | medium |
| `ms_rom_execution_owned_semantic_failure_probability_eq_epsilon_ms_rom_programmability_parameterized` | chains `ms_rom_execution_owned_semantic_failure_probability_eq_local_mass`, `ms_rom_local_failure_mass_eq_parameterized`, and the semantic-to-parameterized equality | `ms_rom_execution_owned_semantic_failure_probability_eq_local_mass` | replace with a direct production-count execution-owned MS2 bridge | medium |
| `A_MS2_rom_programming_execution_owned_parameterized_bound` | currently follows from the equality chain above | none beyond the equality chain above | reprove directly from the new execution-owned MS2 bridge | medium |
| `epsilon_le_rej_semantic_eq_epsilon_le_rej_parameterized` | direct equality between demo semantic rejection epsilon and parameterized rejection epsilon | none; closes by algebra over aliased counts | replace with a production-count rejection bridge inequality or a direct parameterized semantic rejection theorem | low |
| `le_rejection_shadow_semantic_failure_probability_eq_parameterized` | rewrites demo semantic rejection failure probability to the parameterized one through the equality above | `le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic` | replace with a direct parameterized rejection failure-probability bridge | medium |
| `A_LE_rejection_shadow_semantic_failure_probability_le_parameterized_budget` | follows from the preceding equality | none beyond the equality chain above | reprove from the new parameterized rejection failure-probability bridge | medium |
| `A_LE_rejection_sampler_semantic_experiment_sdist_parameterized_bound` | combines the demo experiment theorem with the parameterized rejection budget theorem above | `A_LE_rejection_sampler_semantic_experiment_sdist_le_failure_probability` | keep theorem name, replace lower rejection bridge feeding it | medium |
| `A_LE_rejection_sampler_semantic_sdist_parameterized_bound` | re-exposes the experiment bound above | same as previous row | should survive once the lower rejection bridge is replaced | low |
| `epsilon_le_fs_semantic_eq_epsilon_le_fs_parameterized` | direct equality between demo semantic FS epsilon and parameterized FS epsilon | none; closes by algebra over aliased counts | replace with a production-count FS bridge inequality or a direct parameterized semantic FS theorem | low |
| `le_fs_shadow_local_bad_branch_mass_le_parameterized_failure_probability` | rewrites demo semantic FS epsilon to the parameterized failure probability through the equality above | `LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic` | replace with a direct parameterized FS bad-branch mass bridge | high |
| `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget` | combines the demo FS experiment theorem with the parameterized bad-branch bridge above | `A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass` | keep theorem name, replace lower FS bridge feeding it | high |
| `A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound` | rewrites `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` into the demo public-endpoint theorem | `A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound` | should replay automatically once `A_MS1_hash_binding_execution_owned_parameterized_bound` and its bridge surface are repaired | medium |
| `A_MS2_rom_programming_parameterized_public_endpoint_transition_bound` | rewrites `epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized` into the demo public-endpoint theorem | `A_MS2_rom_programming_semantic_public_endpoint_transition_bound` | should replay automatically once `A_MS2_rom_programming_execution_owned_parameterized_bound` is repaired | medium |
| `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound` | mixed dependency: it does not use an alias equality directly, but it still depends on `A_MS2_rom_programming_execution_owned_parameterized_bound` and the demo-side mass theorem `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure` | `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure` | likely survives unchanged if the MS2 execution-owned parameterized bridge theorem is replaced under the same name; otherwise replay locally | high |
| `A_MS2_rom_programming_parameterized_canonical_game_pr_core_bound` | adds the public-endpoint MS2 theorem and the public-to-canonical landing theorem, thereby paying the same parameterized MS2 budget twice | `A_MS2_rom_programming_parameterized_public_endpoint_transition_bound`, `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound` | retain the theorem shape unless a later direct canonical landing theorem removes the second charge; this is the most expensive MS replay point | high |
| `A_MS1_canonical_hash_binding_parameterized_bound` | directly rewrites `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` into `A_MS1_canonical_hash_binding_semantic_bound` | `A_MS1_canonical_hash_binding_semantic_bound` | replace with a direct canonical parameterized MS1 bound or a theorem that lifts the repaired execution-owned MS1 bridge into the canonical game path | medium |

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

When the parameterized counts diverge from the current demo counts, the first actual breakpoints are the bridge seams, not the top theorem or the game wrappers.

### Breakpoint 1: MS1 execution-owned bridge

Primary file: `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`

Current break cause:

- `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized`
- `ms_hash_binding_execution_owned_semantic_failure_probability_eq_epsilon_ms_hash_binding_parameterized`

Smallest replacement theorem needed:

- `A_MS1_hash_binding_execution_owned_parameterized_bound`

Practical note:

The upper layers want a parameterized execution-owned MS1 bound, not a permanent semantic-to-parameterized equality. Once that theorem is reproved directly from production counts, most MS1 wrappers above it should remain unchanged.

### Breakpoint 2: MS2 execution-owned bridge

Primary file: `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`

Current break cause:

- `epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized`
- `ms_rom_execution_owned_semantic_failure_probability_eq_epsilon_ms_rom_programmability_parameterized`

Smallest replacement theorem needed:

- `A_MS2_rom_programming_execution_owned_parameterized_bound`

Practical note:

This is the most important breakpoint for the full canonical parameterized route because the budgeted public-to-canonical landing theorem consumes this bound.

### Breakpoint 3: LE rejection semantic bridge

Primary file: `le/LERejectionParameterized.ec`

Current break cause:

- `epsilon_le_rej_semantic_eq_epsilon_le_rej_parameterized`
- `le_rejection_shadow_semantic_failure_probability_eq_parameterized`

Smallest replacement theorem needed:

- `A_LE_rejection_sampler_semantic_sdist_parameterized_bound`

Practical note:

The LE wrapper chain above this file appears reusable if this theorem name and its direction are preserved.

### Breakpoint 4: LE FS semantic bridge

Primary file: `le/LEFsProgrammingParameterized.ec`

Current break cause:

- `epsilon_le_fs_semantic_eq_epsilon_le_fs_parameterized`
- `le_fs_shadow_local_bad_branch_mass_le_parameterized_failure_probability`

Smallest replacement theorem needed:

- `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget`

Practical note:

This is likely the hardest LE replay point because it crosses the FS semantic bad-branch mass boundary.

## Recommended Production-Substitution Order

The recommended replay order is:

1. replace parameter aliases in the owner layer while preserving the current parameterized operator names and arithmetic structure
2. replay the LE rejection lower bridge
3. replay the LE FS lower bridge
4. replay the MS1 lower bridge
5. replay the MS2 lower bridge
6. verify that the upper wrappers survive unchanged, replaying only the small number of mixed wrappers that directly rewrote alias equalities
7. rerun the checker and the zero-axiom / zero-admit validation
8. only after the proof route is stable again, revisit readability or refactor work

Reason for this order:

- the owner-layer substitution must come first so every later theorem sees real parameterized counts
- the LE route is more locally contained and should validate the substitution process before touching the canonical MS path
- the MS2 bridge is the most globally visible MS dependency because it feeds both the public-endpoint route and the canonical landing
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

Start with the LE rejection bridge.

Reason:

- it is the smallest bridge seam conceptually
- its upper wrapper chain appears the most reusable unchanged
- it validates the substitution workflow before touching the more expensive MS2 canonical landing path

### Most expensive replay points

The likely highest-cost replay points are:

- `A_MS2_rom_programming_parameterized_canonical_game_pr_core_bound`
- `A_G0_to_G1_ms_parameterized_transition_bound`
- `A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget`

Among these, the MS2 canonical game-pr core theorem is the most architecture-sensitive because it is where the duplicate MS2 charge becomes explicit at the canonical game layer.

### Upper-chain stability assessment

Current assessment:

- the LE upper wrapper chain appears reusable unchanged once the lower rejection and FS bridges are replaced
- the MS upper wrapper chain appears mostly reusable unchanged once the MS1 and MS2 execution-owned bridges are replaced
- `MainTheoremParameterized.ec` appears structurally stable
- the duplicate MS2 charge appears architecturally unavoidable on the current route unless a future direct canonical landing theorem removes it honestly