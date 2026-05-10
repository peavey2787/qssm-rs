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

- `./check_easycrypt.sh`: `OK` over 135 checked theories
- `axiom_count=0`
- `admit_count=0`
- `qssm_main_theorem_parameterized_budget` closed
- exact-zero route unchanged
- demo semantic route unchanged
- public AfterRom still budget-close to canonical AfterRom, not zero-equal
- duplicated MS2 charge still explicit in the canonical parameterized route
- the current `15%r / 32%r` route is frozen for release packaging

Active live profile:

| Component | Active counts | Closed budget |
|---|---|---|
| MS1 | `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32` | `3%r / 32%r` |
| MS2 | `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32` | `3%r / 32%r` |
| LE rejection | `soft=1`, `hard=1`, `invalid=1`, `accept=29`, `failure=3`, `total=32` | `3%r / 32%r` |
| LE FS | `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32` | `3%r / 32%r` |
| LE combined | `epsilon_le_parameterized = epsilon_le_rej_parameterized + epsilon_le_fs_parameterized` | `6%r / 32%r = 3%r / 16%r` |
| Top theorem | `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized` | `15%r / 32%r` |

Lower helper infrastructure now includes `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass` and `primitives/ParameterizedMassHelpers.ec : drange_pred_true_mass_le_bound`. Those lemmas support generic uniform predicate counts on `drange 0 total`, but they do not by themselves expand the supported profile family beyond the current uniform finite-support / contiguous-layout geometry.

## What Can Be Tuned Today Without New Proof Infrastructure

- uniform finite-support totals
- prefix failure counts
- the MS1 contiguous interval upper count
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

Only the frozen `3%r / 32%r` row below is a checked release baseline. The `3%r / 64%r` and `3%r / 128%r` rows are planning placeholders only.

| Profile sketch | `epsilon_MS1` | `epsilon_MS2` | `epsilon_LE_rej` | `epsilon_LE_fs` | `epsilon_LE` | `epsilon_top` |
|---|---:|---:|---:|---:|---:|---|
| Frozen current | `3%r / 32%r` | `3%r / 32%r` | `3%r / 32%r` | `3%r / 32%r` | `3%r / 32%r + 3%r / 32%r` | `3%r / 32%r + 2 * (3%r / 32%r) + (3%r / 32%r + 3%r / 32%r)` |
| Candidate 64 | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r` | `3%r / 64%r + 3%r / 64%r` | `3%r / 64%r + 2 * (3%r / 64%r) + (3%r / 64%r + 3%r / 64%r)` |
| Candidate 128 | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r` | `3%r / 128%r + 3%r / 128%r` | `3%r / 128%r + 2 * (3%r / 128%r) + (3%r / 128%r + 3%r / 128%r)` |

## Stop Conditions

- if the proof requires non-uniform weights, stop and return to profile generalization
- if the support geometry changes, stop
- if the duplicated MS2 charge is accidentally hidden, stop
- if any public AfterRom zero-equality claim appears, stop

## Recommended First Pilot

The first concrete tuning pilot should keep each failure count fixed at `3` and increase only one component's clean suffix support from the current 32-slot family to a 64-slot family.

Recommended order:

1. LE rejection
2. LE FS
3. MS1
4. MS2

This keeps the lower replays local, preserves the frozen theorem surface, and makes any geometry break visible as soon as it appears.