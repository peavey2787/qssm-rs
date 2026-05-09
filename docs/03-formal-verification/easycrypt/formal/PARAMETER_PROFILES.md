# Parameter Profiles

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document is a design-only layer for future concrete parameter selection on the now-closed canonical parameterized theorem route.

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

No concrete production values are selected in this document. Any future rational examples should be labeled illustrative only and not yet production-selected.

## Current Checked Snapshot

- `./check_easycrypt.sh` is `OK` over 133 checked theories; `axiom_count=0`; `admit_count=0`.
- The unchanged demo semantic LE rejection route still uses `soft=1`, `hard=1`, `invalid=1`, `accept=13`, so `epsilon_le_rej_semantic = 3%r / 16%r`.
- The active parameterized LE rejection profile is `soft=1`, `hard=1`, `invalid=1`, `accept=29`, `failure=3`, `total=32`, so `epsilon_le_rej_parameterized = 3%r / 32%r`.
- The active parameterized LE FS profile is `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_le_fs_parameterized = 3%r / 32%r`.
- Those paired `3%r / 32%r` LE profiles now reach `qssm_main_theorem_parameterized_budget` through `LERejectionSamplerParameterizedCore.ec`, `LERejectionSamplerMassLiveParameterized.ec`, `LEFsProgrammingLiveParameterizedCore.ec`, `LEFsProgrammingLiveParameterizedMass.ec`, `LEFsProgrammingParameterizedView.ec`, `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, and `LEStatisticalDistanceParameterized.ec`.
- Together they give `epsilon_le_parameterized = 6%r / 32%r = 3%r / 16%r`.
- The active parameterized MS1 profile is `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_ms_hash_binding_parameterized = 3%r / 32%r`.
- The MS1 canonical failure lane now closes live at `3%r / 32%r`, and the staged public-divergence upper lane now closes live at `2%r / 32%r = 1%r / 16%r`.
- `SourceHashBindingSemanticLiveParameterizedCore.ec` owns the live MS1 coupled-state/public-observable core, `SourceHashBindingSemanticLiveParameterizedMass.ec` owns the live MS1 canonical failure and public-divergence upper mass closure, and `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` now carry the live staged/public-endpoint MS1 route.
- `qssm_main_theorem_parameterized_budget` remains closed with the explicit duplicated MS2 charge.
- The only remaining localized replay seam is `ms_rom_local_failure_mass_le_parameterized_budget`.

## Why The MS2 Charge Appears Twice

The duplicated `epsilon_ms_rom_programmability_parameterized` term is real and must remain explicit.

- First MS2 charge: the staged public AfterRom route still pays the parameterized MS2 ROM-programming transition on the public-endpoint lane.
- Second MS2 charge: the route then pays a separate budgeted public AfterRom to canonical AfterRom landing.
- The second charge is not a formatting artifact and should not be simplified away in theorem prose.
- Public AfterRom is still budget-close to canonical AfterRom, not zero-equal, so the second charge cannot be hidden behind a zero-cost identification.

## Profile Classes

This document uses four planning classes for future concrete parameter selection.

### Demo Profile

Use case: maintain continuity with the current demo-compatible parameterized proof surface while planning eventual non-demo substitution.

- MS1 hash-binding parameterized budget: `epsilon_MS1_demo`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_demo`
- LE rejection parameterized budget: `epsilon_LE_rej_demo`
- LE FS parameterized budget: `epsilon_LE_fs_demo`
- LE umbrella parameterized budget: `epsilon_LE_demo = epsilon_LE_rej_demo + epsilon_LE_fs_demo`
- Full canonical parameterized top budget: `epsilon_top_demo = epsilon_MS1_demo + 2 * epsilon_MS2_demo + epsilon_LE_demo`

Design note: this profile is the closest conceptual match to the currently checked alias-compatible parameterized route.

### Conservative Profile

Use case: choose intentionally loose parameter margins before any production-count substitution is attempted.

- MS1 hash-binding parameterized budget: `epsilon_MS1_conservative`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_conservative`
- LE rejection parameterized budget: `epsilon_LE_rej_conservative`
- LE FS parameterized budget: `epsilon_LE_fs_conservative`
- LE umbrella parameterized budget: `epsilon_LE_conservative = epsilon_LE_rej_conservative + epsilon_LE_fs_conservative`
- Full canonical parameterized top budget: `epsilon_top_conservative = epsilon_MS1_conservative + 2 * epsilon_MS2_conservative + epsilon_LE_conservative`

Design note: this profile is useful when the goal is honest slack rather than tightness.

### Production Candidate Profile

Use case: represent the intended post-substitution parameter surface once actual counts and non-alias lower bridge proofs exist.

- MS1 hash-binding parameterized budget: `epsilon_MS1_prod`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_prod`
- LE rejection parameterized budget: `epsilon_LE_rej_prod`
- LE FS parameterized budget: `epsilon_LE_fs_prod`
- LE umbrella parameterized budget: `epsilon_LE_prod = epsilon_LE_rej_prod + epsilon_LE_fs_prod`
- Full canonical parameterized top budget: `epsilon_top_prod = epsilon_MS1_prod + 2 * epsilon_MS2_prod + epsilon_LE_prod`

Design note: this profile should not be presented as active until the production-count substitution checklist below is complete.

### Stress-Test Profile

Use case: exercise theorem plumbing and sensitivity analysis under intentionally amplified parameter choices.

- MS1 hash-binding parameterized budget: `epsilon_MS1_stress`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_stress`
- LE rejection parameterized budget: `epsilon_LE_rej_stress`
- LE FS parameterized budget: `epsilon_LE_fs_stress`
- LE umbrella parameterized budget: `epsilon_LE_stress = epsilon_LE_rej_stress + epsilon_LE_fs_stress`
- Full canonical parameterized top budget: `epsilon_top_stress = epsilon_MS1_stress + 2 * epsilon_MS2_stress + epsilon_LE_stress`

Design note: this profile is for robustness and readability testing, not for a public security claim.

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

The current parameterized owner/helper layer supports the following profile geometry without new helper lemmas or theorem-surface changes.

- uniform finite-support profiles are supported through the current `drange 0 total` owner pattern
- prefix failure layouts are supported for LE rejection, LE FS, MS1 local failure, and MS2 local failure
- a contiguous interval layout is supported for the MS1 public-divergence upper mass
- larger contiguous uniform supports are structurally supported
- the current live LE rejection pilot is a 32-slot uniform prefix-failure layout; this does not imply arbitrary non-uniform or sparse profiles are supported
- non-uniform weights are not yet supported
- sparse or non-contiguous failure layouts are not yet supported
- reordered MS1/MS2 category branches are not safe without proof changes in the slot-mass and bridge files
- no upper theorem currently depends directly on a literal 16-slot enumeration, but the remaining live lower-budget work is localized at the MS1 and MS2 comparison seams

## Landed Live LE Substitution Slices

The first honest live lower-budget substitution slices are now the LE rejection and LE FS routes.

- `ParameterizedBudgetParameters.ec` changed only the LE rejection owner subfamily to `soft=1`, `hard=1`, `invalid=1`, `accept=29`.
- `LERejectionSamplerParameterizedCore.ec` and `LERejectionSamplerMassLiveParameterized.ec` own the live parameterized rejection core and mass/sdist closure.
- `ParameterizedBudgetParameters.ec` also changed the LE FS owner subfamily to `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=29`.
- `LEFsProgrammingLiveParameterizedCore.ec` and `LEFsProgrammingLiveParameterizedMass.ec` own the live parameterized FS branch/midpoint core and bad-branch mass/sdist closure.
- `LEFsProgrammingParameterizedView.ec`, `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, and `LEStatisticalDistanceParameterized.ec` now carry both live LE components into the combined parameterized route.
- The demo route remains at `3%r / 16%r` per LE component; the active parameterized LE route now carries both LE components at `3%r / 32%r`, so `epsilon_le_parameterized = 3%r / 16%r`.

## Production-Count Substitution Checklist

Before any profile is promoted from design to theorem-facing parameter selection, complete the following work:

1. Choose actual counts for the remaining parameterized MS2 owner if a lower MS2 budget is desired.
2. Replay the remaining localized comparison seam `ms_rom_local_failure_mass_le_parameterized_budget`.
3. Preserve the owner-layer parameterized arithmetic and the explicit duplicated MS2 charge so theorem statements continue to consume the same budget structure.
4. Rerun the full EasyCrypt checker and the zero-axiom / zero-admit validation.
5. Update theorem-facing and release-facing docs after the MS2 bridge proof is locked.

## Explicit Warning About The Current Proof Surface

The current parameterized proof route is structurally complete, and its upper LE/MS bridge paths are now largely de-aliased above the lower comparison layer. The LE rejection route is already past its former demo-arithmetic seam, the MS1 canonical and staged routes are now live parameterized, and the only remaining localized comparison seam still relying on demo arithmetic is MS2 local failure.

The active seams are:

- `ms_rom_local_failure_mass_le_parameterized_budget`

That means the architecture and theorem composition are now in place, and the live LE route plus the live MS1 route have already landed as paired `3%r / 32%r` LE components and a live `3%r / 32%r` / `1%r / 16%r` MS1 pair. Future lowering of the remaining MS family still requires localized lower-proof replacement work before any broader production-count claim is honest.

## MS2 Refactor Candidates Before Production-Count Substitution

This phase does not refactor the MS2 route. The items below are audit targets for later only.

Potential audit targets:

- `ms/MSProbabilitySurfaceParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopCompositionParameterized.ec`

Questions for a later readability pass:

- Can the duplicated MS2 charge be factored into a named `epsilon_ms_rom_programmability_parameterized_canonical_landing` term?
- Can theorem readability improve without hiding the second MS2 charge?
- Can bridge lemmas be renamed to make the first MS2 charge versus the landing MS2 charge clearer?

No such refactor is implemented here. This document records the audit boundary only.