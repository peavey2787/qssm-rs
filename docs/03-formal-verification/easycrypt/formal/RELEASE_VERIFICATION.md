# Release Verification

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document explains how to reproduce the frozen May 2026 release checkpoint and what output to expect.

## Expected Baseline

At the current release checkpoint, the expected result is:

- full checker: `OK: checked 135 theories`
- `axiom_count=0`
- `admit_count=0`
- worktree clean after restoring generated `.eco` churn
- exact-zero route unchanged
- live demo semantic route unchanged
- active parameterized LE rejection profile documented as `soft=1`, `hard=1`, `invalid=1`, `accept=61`, `failure=3`, `total=64`, so `epsilon_le_rej_parameterized = 3%r / 64%r`
- active parameterized LE FS profile documented as `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_le_fs_parameterized = 3%r / 64%r`
- active parameterized LE umbrella documented as `epsilon_le_parameterized = 6%r / 64%r = 3%r / 32%r`
- active parameterized MS1 profile documented as `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_ms_hash_binding_parameterized = 3%r / 32%r`
- MS1 canonical failure lane documented as live at `3%r / 32%r`
- MS1 public-divergence upper lane documented as live at `2%r / 32%r = 1%r / 16%r`
- staged MS1 public-endpoint route documented as live parameterized rather than demo-bound
- active parameterized MS2 profile documented as `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_ms_rom_programmability_parameterized = 3%r / 32%r`
- staged MS2 public-endpoint route documented as live parameterized rather than demo-bound
- no remaining localized replay seams expected on the current uniform finite-support / contiguous-layout profile family
- `qssm_main_theorem_le_parameterized_budget` present and documented as the LE-only intermediate theorem
- `qssm_main_theorem_parameterized_budget` present and documented as the full canonical parameterized theorem
- canonical parameterized top budget documented as `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized`
- active closed-form canonical parameterized top budget documented as `3%r / 8%r`
- lower helper infrastructure documented as including `drange_pred_true_mass` and `drange_pred_true_mass_le_bound` for uniform predicate masses only, not as arbitrary-profile support

## Checker Invocation

From the EasyCrypt directory:

```bash
cd docs/03-formal-verification/easycrypt
./check_easycrypt.sh
```

Expected terminal tail:

```text
OK: checked 135 theories in .../docs/03-formal-verification/easycrypt
```

The compile-order authority remains [../check_easycrypt.sh](../check_easycrypt.sh).

## Axiom And Admit Scans

From the repository root:

```bash
grep -R -n -E '^[[:space:]]*axiom\b' docs/03-formal-verification/easycrypt --include='*.ec' | wc -l
grep -R -n -E '^[[:space:]]*admit\b' docs/03-formal-verification/easycrypt --include='*.ec' | wc -l
```

Expected output:

```text
0
0
```

## Generated `.eco` Expectations

Running the full checker may dirty tracked generated `.eco` files. That churn is not part of the source release.

After a checker run, inspect the worktree:

```bash
git status --short
```

If tracked `.eco` files changed, restore them before asserting release cleanliness:

```bash
git status --short | awk '/\.eco$/ {print $2}' | xargs -r git restore --
```

Then re-check:

```bash
git status --short
```

Expected final output:

```text
<no output>
```

## Claim Boundary Checklist

A release-ready checkpoint must preserve all of the following.

- `BudgetParameters.ec` unchanged
- `MainTheorem.ec` unchanged
- `LERealExecution.ec` unchanged
- `LERejection.ec` unchanged
- demo `LEStatisticalDistance.ec` unchanged
- exact-zero route unchanged
- live demo semantic route unchanged
- semantic top unchanged at `3%r / 4%r`
- active parameterized LE rejection and LE FS routes documented as `3%r / 64%r` while the demo LE rejection and LE FS routes remain `3%r / 16%r`
- active parameterized LE umbrella documented as `epsilon_le_parameterized = 3%r / 32%r`
- active parameterized MS1 profile documented as `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`
- MS1 canonical failure lane documented as live at `3%r / 32%r`
- MS1 public-divergence upper lane documented as live at `2%r / 32%r = 1%r / 16%r`
- staged MS1 public-endpoint route documented as live parameterized rather than demo-bound
- active parameterized MS2 profile documented as `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`
- staged MS2 public-endpoint route documented as live parameterized rather than demo-bound
- `qssm_main_theorem_le_parameterized_budget` documented as the LE-only intermediate theorem
- `qssm_main_theorem_parameterized_budget` documented as the full canonical parameterized theorem
- the explicit duplicated `epsilon_ms_rom_programmability_parameterized` term documented without simplification
- active closed-form canonical parameterized top budget documented as `3%r / 8%r`
- LE rejection and LE FS tuning documented as owner-only changes with no theorem-surface changes and no local proof repairs
- lower helper infrastructure documented as including `drange_pred_true_mass` and `drange_pred_true_mass_le_bound` without implying non-uniform or sparse profile support
- staged/public-endpoint MS caveat documented explicitly as a charged bridge, not a zero bridge
- no remaining localized replay seams expected on the current uniform finite-support / contiguous-layout profile family
- arbitrary non-uniform parameter profiles still documented as unsupported

## What The Release Does Not Claim

The release does not claim a zero-cost public-to-canonical MS fusion.

- Public AfterRom is still budget-close to canonical AfterRom, not zero-equal.
- There is still no theorem claiming `public AfterRom = canonical AfterRom` or `sdist(public AfterRom, canonical AfterRom) = 0`.
- The canonical parameterized route closes by paying an explicit extra `epsilon_ms_rom_programmability_parameterized` term.
- The staged/public-endpoint MS lane remains visible as the internal route consumed by that charged closure, with both the MS1 and MS2 halves now live parameterized.

## Recommended Release Stop

If the checker passes, the axiom/admit scans are zero, the `.eco` churn is restored, and the worktree is clean, the honest stopping point is to stop. Any further work belongs to a later research phase rather than the frozen release surface.