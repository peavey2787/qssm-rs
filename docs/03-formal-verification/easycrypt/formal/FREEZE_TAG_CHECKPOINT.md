# Freeze-Route Tag Checkpoint

This note marks `a873168` as the frozen additive-live-profile checkpoint for the EasyCrypt parameterized theorem route. It is documentation-only and does not change any theorem statement, owner definition, or proof path.

Current head later moved to `OK: checked 142 theories` and added a parallel abstract real-world upper-bound theorem surface, but that later work is additive only and does not change the historical frozen concrete checkpoint recorded here.

## Verification Snapshot

- `./check_easycrypt.sh`: `OK: checked 135 theories`
- `axiom_count=0`
- `admit_count=0`
- verification worktree restored clean after generated `.eco` churn

## Frozen Route Status

- `qssm_main_theorem` unchanged
- `qssm_main_theorem_semantic_budget` unchanged
- `qssm_main_theorem_parameterized_budget` closes through fully live parameterized LE/MS lower lanes
- top parameterized budget: `15%r / 64%r`

## Active Live Profile

- LE rejection: `3%r / 64%r`
- LE FS: `3%r / 64%r`
- LE combined: `6%r / 64%r = 3%r / 32%r`
- MS1: `3%r / 64%r`
- MS1 public-divergence upper interval: `2%r / 64%r = 1%r / 32%r`
- MS2: `3%r / 64%r`, charged twice

## Preserved Invariants

- all four live component lanes active
- no theorem-surface churn across tuning
- duplicate MS2 charge remains explicit
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- exact-zero route unchanged
- demo semantic route unchanged
- support geometry remains limited to uniform finite-support contiguous-layout families
- non-uniform profiles unsupported