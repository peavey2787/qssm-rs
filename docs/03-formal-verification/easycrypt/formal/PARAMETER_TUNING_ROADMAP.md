# Parameter Tuning Roadmap

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document freezes the May 2026 release checkpoint and records the next concrete parameter-tuning path that can be attempted without reopening theorem-surface design.

It is a docs-only planning surface.

- It does not change any EasyCrypt proof file.
- It does not change theorem names.
- It does not weaken the explicit duplicated MS2 charge.
- It does not claim support for non-uniform or sparse profile families.

## Frozen Baseline

Current checker snapshot:

- `./check_easycrypt.sh`: `OK` over 142 checked theories
- `axiom_count=0`
- `admit_count=0`
- `qssm_main_theorem_parameterized_budget` closed
- exact-zero route unchanged
- demo semantic route unchanged
- public AfterRom still budget-close to canonical AfterRom, not zero-equal
- duplicated MS2 charge still explicit in the canonical parameterized route
- the current `15%r / 64%r` route is the checked post-MS2-tuning checkpoint

Active live profile:

| Component | Active counts | Closed budget |
|---|---|---|
| MS1 | `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64` | `3%r / 64%r` |
| MS2 | `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64` | `3%r / 64%r` |
| LE rejection | `soft=1`, `hard=1`, `invalid=1`, `accept=61`, `failure=3`, `total=64` | `3%r / 64%r` |
| LE FS | `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64` | `3%r / 64%r` |
| LE combined | `epsilon_le_parameterized = epsilon_le_rej_parameterized + epsilon_le_fs_parameterized` | `6%r / 64%r = 3%r / 32%r` |
| Top theorem | `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized` | `15%r / 64%r` |

The MS1 staged public-divergence upper lane now closes at `2%r / 64%r = 1%r / 32%r`.

Current head also carries a parallel abstract real-world upper-bound theorem surface through `primitives/RealWorldBudgetParameters.ec`, `primitives/RealWorldBudgetObligations.ec`, `le/LEStatisticalDistanceRealWorld.ec`, `ms/MSProbabilitySurfaceRealWorld.ec`, `games/GameLEBridgeRealWorld.ec`, `games/GameMSHopCompositionRealWorld.ec`, and `theorem/MainTheoremRealWorld.ec`. That surface ends at `qssm_main_theorem_realworld_budget`, is hypothesis-driven rather than axiom-driven, and does not change the concrete tuning surface documented here. It also does not add weighted or non-uniform sampler support.

Lower helper infrastructure now includes `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass`, `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass_le_bound`, `primitives/ParameterizedMassHelpers.ec : drange_subset_true_mass`, `primitives/ParameterizedMassHelpers.ec : drange_subset_true_mass_le_bound`, and `primitives/ParameterizedMassHelpers.ec : drange_subset_complement_mass`. Those lemmas support generic uniform predicate and subset counts on `drange 0 total`, but they do not by themselves expand the supported profile family beyond the current uniform finite-support / contiguous-layout geometry or add non-uniform weights. `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec : ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized` now delegates to the subset-helper sibling theorem while preserving the frozen `15%r / 64%r` route.

The LE rejection, LE FS, MS1, and MS2 `3%r / 64%r` pilots are already landed. All four were owner-only retunings inside the current geometry, changed no theorem surface, and required no local proof repair.

## What Can Be Tuned Today Without New Proof Infrastructure

- uniform finite-support totals
- prefix failure counts
- the current MS1 upper-mass theorem, still over the same contiguous interval support but now routed through subset-helper infrastructure
- the current component ordering, preserved exactly as it is today

Today's safe tuning surface is therefore: keep the existing owner shapes, keep the same theorem names, and change only one uniform count family at a time.

## What Cannot Be Tuned Yet

- non-uniform weights
- sparse or non-contiguous events
- reordered MS1/MS2 category blocks
- arbitrary weighted semantic budgets

If any candidate profile needs one of those changes, it is no longer a tuning-only task. That work returns to profile generalization.

## Safe Concrete Tuning Process

1. Tune one component at a time.
2. Keep all theorem names and theorem-facing wrapper names unchanged.
3. Preserve prefix and interval structure while changing only the targeted owner counts.
4. Run the narrow compile chain for the touched component and then the route up through `theorem/MainTheoremParameterized.ec` and `theorem/MainTheorem.ec`.
5. If the narrow chain passes, run the full checker and the zero-axiom / zero-admit validation.
6. Update release-facing docs only after the proof route is checker-green again.

## Candidate Tuning Directions

- reduce component budgets by increasing clean suffix support
- keep failure count fixed and increase total support
- preserve the current prefix and interval structure
- evaluate the resulting top bound with the MS2 term charged twice

The planning formula remains:

```text
epsilon_LE = epsilon_LE_rej + epsilon_LE_fs

epsilon_top = epsilon_MS1 + 2 * epsilon_MS2 + epsilon_LE
```

## Concrete Example Table

Only the `Current checked baseline` row below is checker-validated today. The remaining row is a planning placeholder only.

| Profile sketch | `epsilon_MS1` | `epsilon_MS2` | `epsilon_LE_rej` | `epsilon_LE_fs` | `epsilon_LE` | `epsilon_top` |
|---|---:|---:|---:|---:|---:|---|
| Current checked baseline | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r + 3%r / 64%r` | `3%r / 64%r + 2 * (3%r / 64%r) + (3%r / 64%r + 3%r / 64%r)` |
| All-components 128 candidate | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r + 3%r / 128%r` | `3%r / 128%r + 2 * (3%r / 128%r) + (3%r / 128%r + 3%r / 128%r)` |

## Stop Conditions

- if the proof requires non-uniform weights, stop and return to profile generalization
- if the support geometry changes, stop
- if the duplicated MS2 charge is accidentally hidden, stop
- if any public AfterRom zero-equality claim appears, stop

## Completed And Next Pilots

The first four concrete tuning pilots kept each failure count fixed at `3` and increased only one owner's clean suffix support at a time.

Completed order:

1. LE rejection
2. LE FS
3. MS1
4. MS2

Next recommended phase:

1. Weighted finite-support replay design audit if non-uniform or externally measured sampler semantics are required
2. Stop at the current split surfaces if the frozen concrete route and abstract upper-bound route are sufficient

This keeps the lower replays local, preserves the frozen theorem surface, and makes any geometry break visible as soon as it appears.