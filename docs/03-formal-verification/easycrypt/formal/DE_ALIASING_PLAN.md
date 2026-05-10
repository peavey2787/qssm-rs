# De-Aliasing Plan

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document audits the current parameterized proof lane for profile-generalization readiness.

The current de-aliasing/live replay campaign is complete for the active uniform finite-support / contiguous-layout live family. What remains is not a pending localized seam replay; it is future work for broader profile families or tighter lower semantics.

Current head also carries a parallel abstract real-world upper-bound theorem surface above the same live lower masses. That additive route does not change the de-aliasing verdict here and does not implement weighted or non-uniform sampler semantics.

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
- `ms/source/SourceHashBindingSemanticLiveParameterizedCore.ec`
- `ms/source/SourceHashBindingSemanticLiveParameterizedMass.ec`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticLiveParameterizedCore.ec`
- `ms/comparison/ComparisonPayloadSemanticLiveParameterizedMass.ec`
- `le/LERejectionSamplerParameterizedCore.ec`
- `le/LERejectionSamplerMassLiveParameterized.ec`
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`
- `le/LEFsProgrammingLiveParameterizedCore.ec`
- `le/LEFsProgrammingLiveParameterizedMass.ec`

### Bridge layer

This layer packages lower parameterized facts into theorem-facing parameterized lanes.

- `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `le/LERejectionParameterized.ec`
- `le/LEFsProgrammingParameterized.ec`
- `le/LEFsProgrammingParameterizedView.ec`
- `ms/MSProbabilitySurfaceParameterized.ec`

### Wrapper layer

This layer packages lower bounds into reusable parameterized MS and LE wrappers.

- `le/LEStatisticalDistanceParameterized.ec`
- `le/LEHVZKParameterized.ec`
- `games/GameLEBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopTypesParameterized.ec`

### Game layer

This layer re-enters the canonical game hop with the explicit duplicated MS2 landing charge.

- `games/GameMSHopCompositionParameterized.ec`

### Top-level layer

This layer exposes the public parameterized theorem surface.

- `theorem/MainTheoremParameterized.ec`

## Parallel Abstract Real-World Surface

The current head additionally carries an axiom-free abstract upper-bound route.

### Real-world budget and obligation layer

- `primitives/RealWorldBudgetParameters.ec`
- `primitives/RealWorldBudgetObligations.ec`

### Real-world wrapper, game, and top layers

- `le/LEStatisticalDistanceRealWorld.ec`
- `ms/MSProbabilitySurfaceRealWorld.ec`
- `games/GameLEBridgeRealWorld.ec`
- `games/GameMSHopCompositionRealWorld.ec`
- `theorem/MainTheoremRealWorld.ec`

That route ends at `qssm_main_theorem_realworld_budget`, consumes explicit `le_realworld_obligations`, `ms_realworld_obligations`, and `qssm_realworld_obligations` hypotheses, keeps the duplicate MS2 charge explicit, and preserves the public AfterRom budget-close caveat. It is additive only: it does not replay weighted/non-uniform samplers and therefore does not remove the future-generalization hotspots listed below. It is already sufficient when real-world sampler evidence stays external to the EasyCrypt tree.

## Classification Vocabulary

This audit uses three classes.

- `live-route`: the theorem or file is part of the active live parameterized route on the current frozen family.
- `compatibility-only`: the theorem is an equality or exact companion kept for compatibility/history, not required by the active live route.
- `future-generalization hotspot`: the theorem or file is likely to need replay if the supported profile geometry changes.

## Structurally Durable Components

These components should remain part of the architecture even if broader profile families are introduced later.

### Parameterized owner arithmetic

`primitives/ParameterizedBudgetParameters.ec` now carries active non-demo parameter values directly for LE, MS1, and MS2.

- Component-sum lemmas such as `ms1_param_failure_count_component_sum` and `ms2_param_failure_count_component_sum` are genuine arithmetic.
- Nonnegativity and positivity lemmas such as `epsilon_ms_hash_binding_parameterized_nonneg`, `epsilon_ms_rom_programmability_parameterized_nonneg`, `epsilon_le_rej_parameterized_nonneg`, `epsilon_le_fs_parameterized_nonneg`, and `epsilon_le_parameterized_nonneg` are genuine arithmetic over the parameterized operators.
- The owner-layer additive structure `epsilon_le_parameterized = epsilon_le_rej_parameterized + epsilon_le_fs_parameterized` is already the right long-term architecture.
- `primitives/ParameterizedMassHelpers.ec` now also carries `drange_pred_true_mass` and `drange_pred_true_mass_le_bound`, which package generic uniform predicate masses and upper bounds for the current `drange 0 total` owner pattern without widening theorem-surface support beyond the current uniform finite-support / contiguous-layout family.

Classification: `live-route` and structurally durable.

### Live lower owners and mass closures

The active lower route is now live on LE, MS1, and MS2.

- `SourceHashBindingSemanticSlotMassParameterized.ec`, `SourceHashBindingSemanticLiveParameterizedCore.ec`, and `SourceHashBindingSemanticLiveParameterizedMass.ec` own the live MS1 lower route.
- `ComparisonPayloadSemanticSlotMassParameterized.ec`, `ComparisonPayloadSemanticLiveParameterizedCore.ec`, and `ComparisonPayloadSemanticLiveParameterizedMass.ec` own the live MS2 lower route.
- `LERejectionSamplerParameterizedCore.ec` and `LERejectionSamplerMassLiveParameterized.ec` own the live LE rejection route.
- `LEFsProgrammingFailureProbabilityParameterized.ec`, `LEFsProgrammingLiveParameterizedCore.ec`, and `LEFsProgrammingLiveParameterizedMass.ec` own the live LE FS route.

Classification: `live-route`.

### Upper wrapper structure

The upper wrapper architecture is the right long-term one.

- `le/LEStatisticalDistanceParameterized.ec`
- `le/LEHVZKParameterized.ec`
- `games/GameLEBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopTypesParameterized.ec`
- `games/GameMSHopCompositionParameterized.ec`
- `theorem/MainTheoremParameterized.ec`

These files primarily compose lower bounds and preserve the explicit theorem-facing budget structure.

Classification: `live-route` and structurally stable.

## Active Route Completion State

The active route is now live end to end.

- LE rejection closes through `LERejectionSamplerParameterizedCore.ec -> LERejectionSamplerMassLiveParameterized.ec -> LERejectionParameterized.ec`.
- LE FS closes through `LEFsProgrammingLiveParameterizedCore.ec -> LEFsProgrammingLiveParameterizedMass.ec -> LEFsProgrammingParameterized.ec`.
- MS1 closes through `SourceHashBindingSemanticLiveParameterizedCore.ec -> SourceHashBindingSemanticLiveParameterizedMass.ec -> SourceHashBindingSemanticBridgeParameterized.ec`.
- MS2 closes through `ComparisonPayloadSemanticLiveParameterizedCore.ec -> ComparisonPayloadSemanticLiveParameterizedMass.ec -> ComparisonPayloadSemanticBridgeParameterized.ec`.
- `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, `GameMSHopCompositionParameterized.ec`, and `MainTheoremParameterized.ec` now consume those live lower lanes without reopening a demo/parameterized seam on the active family.
- The active top budget remains `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized`, which evaluates to `15%r / 64%r` on the current frozen family.
- `primitives/ParameterizedMassHelpers.ec` now also carries the uniform subset helpers `drange_subset_true_mass`, `drange_subset_true_mass_le_bound`, and `drange_subset_complement_mass`, and `SourceHashBindingSemanticSlotMassParameterized.ec : ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized` now routes through that subset-helper layer with unchanged theorem name, statement, and active `15%r / 64%r` closure.
- The LE rejection, LE FS, MS1, and MS2 owner retunings to `3%r / 64%r` landed without theorem-surface changes or local proof repairs.
- No remaining localized count-alias-sensitive seams are expected on the current uniform finite-support / contiguous-layout family.

## Compatibility-Only Equalities Kept For History

The following equalities may still exist as compatibility shims or proof-history artifacts, but they are not part of the active live route.

| Theorem | Current role | Guidance if profiles broaden |
|---|---|---|
| `epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized` | compatibility-only equality between demo semantic and parameterized MS1 owners | keep only as a compatibility shim or retire it from the active route |
| `ms_hash_binding_local_public_divergence_upper_mass_eq_parameterized` | compatibility-only equality for the staged MS1 upper mass | prefer replaying the live comparison theorem rather than routing through this equality |
| `epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized` | compatibility-only equality between demo semantic and parameterized MS2 owners | keep only as a compatibility shim or retire it from the active route |
| `ms_rom_local_failure_mass_eq_parameterized` | compatibility-only equality between demo local failure mass and the parameterized owner | do not treat it as an active-route dependency |
| `ms_rom_execution_owned_semantic_failure_probability_eq_epsilon_ms_rom_programmability_parameterized` | compatibility-only exact companion above the old comparison surface | prefer replaying the live MS2 route instead |
| `epsilon_le_fs_semantic_eq_epsilon_le_fs_parameterized` | compatibility-only equality between demo semantic and parameterized LE FS owners | keep only as a compatibility shim if still useful for proof history |

Classification: `compatibility-only`.

## Future Generalization Hotspots

If the profile family changes, there is no single currently open seam to replay. The first breakpoints will be the owner geometry and the lower files that interpret it.

Primary hotspots:

- `primitives/ParameterizedBudgetParameters.ec` when counts, weights, or support geometry change
- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`, `SourceHashBindingSemanticLiveParameterizedCore.ec`, and `SourceHashBindingSemanticLiveParameterizedMass.ec` for MS1 geometry changes
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`, `ComparisonPayloadSemanticLiveParameterizedCore.ec`, and `ComparisonPayloadSemanticLiveParameterizedMass.ec` for MS2 geometry changes
- `le/LERejectionSamplerParameterizedCore.ec` and `LERejectionSamplerMassLiveParameterized.ec` for LE rejection geometry changes
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`, `LEFsProgrammingLiveParameterizedCore.ec`, and `LEFsProgrammingLiveParameterizedMass.ec` for LE FS geometry changes

These are the files most likely to require real replay if future work moves beyond the current uniform finite-support / contiguous-layout family or introduces non-uniform weights. The parallel abstract real-world surface does not reduce that replay cost because it packages upper bounds rather than new sampler semantics.

Classification: `future-generalization hotspot`.

## Weighted Replay Audit Conclusion

The weighted finite-support replay audit is now complete.

- Weighted replay is only needed if this repository must model weighted sampler internals directly.
- The preferred future owner shape is normalized per-component category weights.
- Per-slot weights are not the right first move because they widen the replay surface without improving the theorem boundary.
- Component-failure-only weighted records are too abstract because they mostly duplicate `le_realworld_obligations`, `ms_realworld_obligations`, and `qssm_realworld_obligations`.
- The first safe weighted pilot, if ever approved, is an LE rejection weighted category owner only.
- `qssm_main_theorem_realworld_budget` remains the correct top theorem; any weighted replay should discharge obligations below it rather than replace it.

## Recommended Future Order

If parameterized work resumes here, the recommended order is:

1. Preserve the current parameterized operator names, theorem names, arithmetic structure, and the explicit duplicated MS2 charge.
2. Generalize one owner family at a time and replay the affected lower slot-mass, coupled-state, and public-observable theorems.
3. Verify that the upper wrappers above the changed owner survive unchanged.
4. Rerun the checker and the zero-axiom / zero-admit validation.
5. Only after the proof route is stable again, revisit readability or refactor work.

Reason for this order:

- the live LE rejection, live LE FS, live MS1, and live MS2 routes have already validated the substitution process on the current family without disturbing the theorem-facing route
- future risk now comes from changing the supported family itself, not from an already-identified missing bridge on the active route
- delaying readability work avoids mixing mathematical changes with naming churn

## Structural Invariants That Must Remain Frozen

The following invariants must stay unchanged during future generalization work.

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
| target LE budget | `epsilon_LE_target` | `epsilon_LE_rej + epsilon_LE_fs <= epsilon_LE_target` |
| acceptable MS2 landing penalty | `epsilon_MS2_landing_target` | `epsilon_MS2_landing <= epsilon_MS2_landing_target` |

These are planning variables only. They are not proof constants and are not yet production-selected values.

## Optional Future Cleanup Candidates

These are intentionally deferred until after any future profile generalization succeeds.

- naming cleanup for the parameterized bridge theorems
- readability cleanup in `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, and `GameMSHopCompositionParameterized.ec`
- factoring the second MS2 charge into a named landing term if that can be done without hiding the duplicated charge
- theorem inventory tooling for parameterized versus demo routes
- import-graph tooling for the EasyCrypt proof tree

## Recommendations

### First future audit target

No further audit is required unless sampler-internal weighted semantics become a hard requirement.

Reason:

- the LE rejection, LE FS, MS1, and MS2 live parameterized routes are already landed and checker-green
- the abstract real-world upper-bound theorem is already sufficient for externally justified bounds
- no remaining localized seam is expected on the current frozen family
- the next nontrivial work item, if reopened, is either broadening the supported family or starting a narrowly scoped weighted pilot below the theorem surface

If weighted replay is ever reopened, start with an LE rejection weighted category owner rather than a full-route or per-slot rewrite.

### Most expensive future replay points

If profile geometry changes materially, the likely highest-cost replay points are:

- `ComparisonPayloadSemanticLiveParameterizedCore.ec`
- `ComparisonPayloadSemanticLiveParameterizedMass.ec`
- `MSProbabilitySurfaceParameterized.ec`
- `GameAdvantageParameterized.ec`
- `GameMSHopCompositionParameterized.ec`

These are the files where lower-geometry changes are most likely to surface again as theorem-routing work.

### Upper-chain stability assessment

Current assessment:

- the LE upper wrapper chain is structurally de-aliased on the active route
- the MS execution-owned and public-endpoint wrapper chain is structurally de-aliased on the active route
- `MainTheoremParameterized.ec` appears structurally stable
- the duplicate MS2 charge appears architecturally unavoidable on the current route unless a future direct canonical landing theorem removes it honestly
