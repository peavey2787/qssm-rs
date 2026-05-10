# Parameter Profiles

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document records the active live parameter profiles on the closed canonical parameterized theorem route and the constraints for any future profile generalization work.

It does not change any EasyCrypt constants, does not mutate `ParameterizedBudgetParameters.ec`, does not mutate `BudgetParameters.ec`, and does not change any theorem statement.

## Current Proven Symbolic Top Budget

The current closed top-level parameterized theorem is `theorem/MainTheoremParameterized.ec : qssm_main_theorem_parameterized_budget`.

Its proven symbolic budget is:

```text
epsilon_ms_hash_binding_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_le_parameterized
```

For planning purposes, it is convenient to name the same slots as:

```text
epsilon_MS1 := epsilon_ms_hash_binding_parameterized
epsilon_MS2 := epsilon_ms_rom_programmability_parameterized
epsilon_LE_rej := epsilon_le_rej_parameterized
epsilon_LE_fs := epsilon_le_fs_parameterized
epsilon_LE := epsilon_le_parameterized
```

Then the theorem-level expression is:

```text
epsilon_LE = epsilon_LE_rej + epsilon_LE_fs

epsilon_top_parameterized =
  epsilon_MS1 + 2 * epsilon_MS2 + epsilon_LE
```

Under the active live profiles, that symbolic top budget evaluates to `15%r / 64%r`.

## Current Checked Snapshot

- `./check_easycrypt.sh` is `OK` over 142 checked theories; `axiom_count=0`; `admit_count=0`.
- The unchanged demo semantic LE rejection route still uses `soft=1`, `hard=1`, `invalid=1`, `accept=13`, so `epsilon_le_rej_semantic = 3%r / 16%r`.
- The active parameterized LE rejection profile is `soft=1`, `hard=1`, `invalid=1`, `accept=61`, `failure=3`, `total=64`, so `epsilon_le_rej_parameterized = 3%r / 64%r`.
- The active parameterized LE FS profile is `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_le_fs_parameterized = 3%r / 64%r`.
- Those paired `3%r / 64%r` LE profiles now reach `qssm_main_theorem_parameterized_budget` through `LERejectionSamplerParameterizedCore.ec`, `LERejectionSamplerMassLiveParameterized.ec`, `LEFsProgrammingLiveParameterizedCore.ec`, `LEFsProgrammingLiveParameterizedMass.ec`, `LEFsProgrammingParameterizedView.ec`, `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, and `LEStatisticalDistanceParameterized.ec`.
- Together they give `epsilon_le_parameterized = 6%r / 64%r = 3%r / 32%r`.
- The active parameterized MS1 profile is `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_ms_hash_binding_parameterized = 3%r / 64%r`.
- The MS1 canonical failure lane now closes live at `3%r / 64%r`, and the staged public-divergence upper lane now closes live at `2%r / 64%r = 1%r / 32%r`.
- `SourceHashBindingSemanticLiveParameterizedCore.ec` owns the live MS1 coupled-state/public-observable core, `SourceHashBindingSemanticLiveParameterizedMass.ec` owns the live MS1 canonical failure and public-divergence upper mass closure, and `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` now carry the live staged/public-endpoint MS1 route.
- The active parameterized MS2 profile is `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_ms_rom_programmability_parameterized = 3%r / 64%r`.
- `ComparisonPayloadSemanticLiveParameterizedCore.ec` owns the live MS2 category/coupled-state/public-AfterRom core, `ComparisonPayloadSemanticLiveParameterizedMass.ec` owns the live MS2 execution-owned failure and public-divergence/failure mass closure, and `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` now carry the live staged/public-endpoint MS2 route and the budgeted public-to-canonical landing.
- The LE rejection, LE FS, MS1, and MS2 retunings were owner-only changes. They changed no theorem surface and required no local proof repairs.
- `qssm_main_theorem_parameterized_budget` remains closed with the explicit duplicated MS2 charge.
- No remaining localized replay seams are expected on the current uniform finite-support / contiguous-layout profile family.

## Parallel Abstract Real-World Surface

The current head also carries a separate axiom-free abstract upper-bound theorem surface.

- `primitives/RealWorldBudgetParameters.ec` defines the explicit `realworld_budget` bundle and the operators `epsilon_ms_hash_binding_realworld`, `epsilon_ms_rom_programmability_realworld`, `epsilon_le_rej_realworld`, `epsilon_le_fs_realworld`, `epsilon_le_realworld`, and `epsilon_top_realworld`.
- `primitives/RealWorldBudgetObligations.ec` packages `le_realworld_obligations`, `ms_realworld_obligations`, and `qssm_realworld_obligations`.
- `le/LEStatisticalDistanceRealWorld.ec`, `ms/MSProbabilitySurfaceRealWorld.ec`, `games/GameLEBridgeRealWorld.ec`, `games/GameMSHopCompositionRealWorld.ec`, and `theorem/MainTheoremRealWorld.ec` lift those hypotheses into `qssm_main_theorem_realworld_budget`.
- Those obligations are theorem hypotheses, not axioms.
- This surface models externally supplied upper-bound budgets only. That is already sufficient when sampler internals are justified by external evidence. It does not yet implement weighted or non-uniform sampler semantics, and it leaves the frozen concrete `15%r / 64%r` route unchanged.

## Weighted Replay Audit Conclusion

The weighted finite-support replay audit is complete.

- Weighted replay is only needed if this repository must model weighted sampler internals directly rather than consume externally justified upper-bound budgets.
- The preferred future owner shape is normalized per-component category weights.
- Per-slot weights are not the right first move because they widen replay cost without improving the theorem surface.
- Component-failure-only records are too abstract because they mostly duplicate the current real-world obligations.
- The first safe weighted pilot, if later approved, is an LE rejection weighted category owner only.

## Why The MS2 Charge Appears Twice

The duplicated `epsilon_ms_rom_programmability_parameterized` term is real and must remain explicit.

- First MS2 charge: the staged public AfterRom route pays the parameterized MS2 ROM-programming transition on the public-endpoint lane.
- Second MS2 charge: the route then pays a separate budgeted public AfterRom to canonical AfterRom landing.
- The second charge is not a formatting artifact and should not be simplified away in theorem prose.
- Public AfterRom is still budget-close to canonical AfterRom, not zero-equal, so the second charge cannot be hidden behind a zero-cost identification.

## Profile Classes

This document uses four planning classes for any future concrete parameter selection.

### Demo Profile

Use case: maintain continuity with the current symbolic theorem structure while discussing the same slot layout abstractly.

- MS1 hash-binding parameterized budget: `epsilon_MS1_demo`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_demo`
- LE rejection parameterized budget: `epsilon_LE_rej_demo`
- LE FS parameterized budget: `epsilon_LE_fs_demo`
- LE umbrella parameterized budget: `epsilon_LE_demo = epsilon_LE_rej_demo + epsilon_LE_fs_demo`
- Full canonical parameterized top budget: `epsilon_top_demo = epsilon_MS1_demo + 2 * epsilon_MS2_demo + epsilon_LE_demo`

### Conservative Profile

Use case: choose intentionally loose parameter margins before any broader profile generalization is attempted.

- MS1 hash-binding parameterized budget: `epsilon_MS1_conservative`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_conservative`
- LE rejection parameterized budget: `epsilon_LE_rej_conservative`
- LE FS parameterized budget: `epsilon_LE_fs_conservative`
- LE umbrella parameterized budget: `epsilon_LE_conservative = epsilon_LE_rej_conservative + epsilon_LE_fs_conservative`
- Full canonical parameterized top budget: `epsilon_top_conservative = epsilon_MS1_conservative + 2 * epsilon_MS2_conservative + epsilon_LE_conservative`

### Production Candidate Profile

Use case: represent an intended future profile once new owner geometry and any required lower replays are checker-green.

- MS1 hash-binding parameterized budget: `epsilon_MS1_prod`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_prod`
- LE rejection parameterized budget: `epsilon_LE_rej_prod`
- LE FS parameterized budget: `epsilon_LE_fs_prod`
- LE umbrella parameterized budget: `epsilon_LE_prod = epsilon_LE_rej_prod + epsilon_LE_fs_prod`
- Full canonical parameterized top budget: `epsilon_top_prod = epsilon_MS1_prod + 2 * epsilon_MS2_prod + epsilon_LE_prod`

### Stress-Test Profile

Use case: exercise theorem plumbing and sensitivity analysis under intentionally amplified parameter choices.

- MS1 hash-binding parameterized budget: `epsilon_MS1_stress`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_stress`
- LE rejection parameterized budget: `epsilon_LE_rej_stress`
- LE FS parameterized budget: `epsilon_LE_fs_stress`
- LE umbrella parameterized budget: `epsilon_LE_stress = epsilon_LE_rej_stress + epsilon_LE_fs_stress`
- Full canonical parameterized top budget: `epsilon_top_stress = epsilon_MS1_stress + 2 * epsilon_MS2_stress + epsilon_LE_stress`

## Slot Template For Any Future Concrete Profile

Any concrete profile should fill the same slot template.

| Slot | Symbolic owner | Profile-specific placeholder |
|---|---|---|
| MS1 hash-binding | `epsilon_ms_hash_binding_parameterized` | `epsilon_MS1_*` |
| MS2 ROM-programming | `epsilon_ms_rom_programmability_parameterized` | `epsilon_MS2_*` |
| LE rejection | `epsilon_le_rej_parameterized` | `epsilon_LE_rej_*` |
| LE FS | `epsilon_le_fs_parameterized` | `epsilon_LE_fs_*` |
| LE umbrella | `epsilon_le_parameterized` | `epsilon_LE_* = epsilon_LE_rej_* + epsilon_LE_fs_*` |
| Full canonical top budget | theorem-level sum | `epsilon_top_* = epsilon_MS1_* + 2 * epsilon_MS2_* + epsilon_LE_*` |

The `*` placeholder stands for `demo`, `conservative`, `prod`, or `stress`.

## Supported Profile Geometry

The current parameterized owner/helper layer supports the following geometry without new helper lemmas or theorem-surface changes.

- uniform finite-support profiles are supported through the current `drange 0 total` owner pattern
- generic uniform predicate masses on `dmap (drange 0 total)` are now supported through `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass` and `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass_le_bound`
- generic uniform subset masses represented by list membership on `dmap (drange 0 total)` are now supported through `primitives/ParameterizedMassHelpers.ec : drange_subset_true_mass`, `primitives/ParameterizedMassHelpers.ec : drange_subset_true_mass_le_bound`, and `primitives/ParameterizedMassHelpers.ec : drange_subset_complement_mass`
- prefix failure layouts are supported for LE rejection, LE FS, MS1 local failure, and MS2 local failure
- the active MS1 public-divergence upper mass is still a contiguous interval event on the frozen family, but its routed lower theorem now delegates to the subset-helper layer in `SourceHashBindingSemanticSlotMassParameterized.ec`
- larger contiguous uniform supports are structurally supported
- those generic predicate and subset helpers are lower helper infrastructure only; they do not add non-uniform weights, sparse support, or theorem-surface support for arbitrary profile families
- the current frozen live family is a uniform 64-slot finite-support / contiguous-layout profile with three failure slots on each active parameterized owner
- non-uniform weights are not yet supported
- sparse or non-contiguous failure layouts are not yet supported
- reordered MS1/MS2 category branches are not safe without proof changes in the slot-mass and bridge files
- no remaining localized replay seams are expected on the current supported family; future work begins when the family itself changes

## Landed Live Route Components

The active parameterized theorem route is fully live on LE, MS1, and MS2.

- LE rejection: `LERejectionSamplerParameterizedCore.ec` and `LERejectionSamplerMassLiveParameterized.ec` own the live parameterized rejection core and mass/sdist closure at `3%r / 64%r`.
- LE FS: `LEFsProgrammingLiveParameterizedCore.ec` and `LEFsProgrammingLiveParameterizedMass.ec` own the live parameterized FS branch/midpoint core and bad-branch mass/sdist closure at `3%r / 64%r`.
- MS1: `SourceHashBindingSemanticLiveParameterizedCore.ec` and `SourceHashBindingSemanticLiveParameterizedMass.ec` own the live MS1 canonical failure and staged/public-endpoint route at `3%r / 64%r` and `1%r / 32%r`.
- MS2: `ComparisonPayloadSemanticLiveParameterizedCore.ec` and `ComparisonPayloadSemanticLiveParameterizedMass.ec` own the live MS2 staged/public-endpoint and landing route at `3%r / 64%r`.
- The resulting top budget remains `epsilon_MS1 + 2 * epsilon_MS2 + epsilon_LE`, which evaluates to `15%r / 64%r` on the active live family.

## Profile Generalization Checklist

Before any profile is promoted beyond the current frozen family, complete the following work:

1. Choose the new counts or weights and identify which owner geometry changes relative to the current uniform finite-support / contiguous-layout family.
2. Replay the affected lower slot-mass, coupled-state, and public-observable theorems in the MS1, MS2, and LE files touched by that geometry change.
3. Preserve the owner-layer arithmetic and the explicit duplicated MS2 charge so theorem statements continue to consume the same budget structure.
4. Rerun the full EasyCrypt checker and the zero-axiom / zero-admit validation.
5. Update theorem-facing and release-facing docs after the new profile family is checker-green.

## Explicit Warning About The Current Proof Surface

The current parameterized proof route is structurally complete for the active uniform finite-support / contiguous-layout live family. That does not imply arbitrary non-uniform, sparse, or reordered profiles are supported, and it does not remove the semantic caveat that public AfterRom is only budget-close to canonical AfterRom. The parallel real-world theorem surface does not change that interpretation: it consumes externally supplied upper-bound budgets as hypotheses and still does not justify weighted/non-uniform sampler claims. If weighted replay is ever pursued, it should discharge those hypotheses below `qssm_main_theorem_realworld_budget` rather than replace that theorem surface.

Future work therefore starts from profile generalization or stronger lower semantics, not from replaying a currently open localized seam on the active route.

## Future Refactor Candidates

This release does not refactor the parameterized MS route further. The items below remain optional follow-up work only.

Potential audit targets:

- `ms/MSProbabilitySurfaceParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopCompositionParameterized.ec`

Questions for a later readability pass:

- Can the duplicated MS2 charge be factored into a named landing term without hiding it?
- Can theorem readability improve without obscuring the second MS2 charge?
- Can bridge lemmas be renamed to make the staged MS2 charge versus the landing MS2 charge clearer?