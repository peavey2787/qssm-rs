# LE Refinement Plan

Navigation: [EasyCrypt README](../README.md)

## Goal

The current LE theorem path is checker-green, componentized, and stable, but it still closes on an exact-zero model. The next refinement objective is to make the lower LE rejection and FS semantics progressively less identity-shaped without destabilizing the theorem-facing path.

## Current State

The live theorem-facing arithmetic is already decomposed:

- `epsilon_le = epsilon_le_rej + epsilon_le_fs`
- `le/LERejection.ec` ends the rejection leg in `epsilon_le_rej`
- `le/LEFsProgramming.ec` ends the FS leg in `epsilon_le_fs`
- `le/LEStatisticalDistance.ec` composes those two legs additively and rewrites to `epsilon_le`

Both theorem-facing component endpoints already route through lower semantic shadow lanes.

## Rejection Lane

What is already in place:

- `le/LERejectionSampler.ec` owns a semantic coupled-state shadow rejection surface
- the shadow pre/post marginals bridge back to `d_le_real_view` and `d_le_post_rejection_view`
- `le/LERejection.ec` proves the shadow sdist-vs-failure and failure-vs-budget theorems
- the theorem-facing endpoint `A_LE_rejection_sampler_sdist_bound` already routes through that shadow lane

What remains true today:

- the current shadow failure quantity still collapses to zero on the active carrier
- `epsilon_le_rej` therefore stays at `0%r` on the current model

## FS Lane

What is already in place:

- `le/LEFsProgrammingSurface.ec` owns a semantic coupled-state shadow FS lane
- structural bridge lemmas connect the shadow pre/post marginals back to `d_le_post_rejection_view`, `d_le_sim_view`, and the theorem-facing programmed-view surfaces
- the quantitative shadow theorems are already proved on the current model:
  - `d_le_fs_shadow_pre_post_marginals_equal`
  - `le_fs_shadow_failure_probability_zero`
  - `A_LE_fs_shadow_sdist_le_failure_probability`
  - `A_LE_fs_shadow_failure_probability_le_budget`
- `le/LEFsProgramming.ec` already routes the theorem-facing component endpoint through those shadow theorems while keeping the downstream theorem-facing names stable

What remains blocked:

- the active bad-event semantics are still exact-zero on the current carrier
- the attempted branch-sensitive refinement did not land because one local theorem is still missing

## Immediate Next Local Target

The next exact theorem to prove is:

- a support-aware good-branch collapse result for a branch-sensitive `le_fs_shadow_post_of_observable` on the support of `d_le_pre_fs_programming_view x s`

That theorem is the missing ingredient needed to recover:

- `d_le_fs_shadow_post_marginal_matches_programmed_view`
- `d_le_fs_shadow_pre_post_marginals_equal`

without falling back to pure definitional identity transport.

## Guardrails

The intended refinement path should keep the following stable unless there is a compelling reason to change them:

- theorem-facing names in `LERejection.ec`, `LEFsProgramming.ec`, and `LEModel.ec`
- the component-budget arithmetic in `LEStatisticalDistance.ec`
- the top-level theorem packaging in `LEHVZK.ec`, `games/GameLEBridge.ec`, and `theorem/MainTheorem.ec`

The preferred workflow is:

1. refine the lower shadow carrier
2. close the local structural and quantitative theorems on that carrier
3. route the theorem-facing endpoint through the new lower result
4. only then consider widening the arithmetic or budget surface

## Future Budget Restoration

Today the LE budgets are concrete zeros. A future realistic LE model should restore nonzero budget formulas only after the lower semantic surfaces justify them.

The likely order is:

1. make the FS shadow bad-event semantics nontrivial
2. derive or upper-bound a nonzero `epsilon_le_fs` from that refined failure quantity
3. if the rejection surface becomes nontrivial, derive or upper-bound a nonzero `epsilon_le_rej`
4. keep the umbrella identity `epsilon_le = epsilon_le_rej + epsilon_le_fs`
5. leave theorem-facing arithmetic unchanged unless the lower semantics force a different decomposition

## Detailed References

- [LE_HVZK_proof_plan.md](LE_HVZK_proof_plan.md)
- [../formal/PROOF_STATUS.md](../formal/PROOF_STATUS.md)
- [../formal/ASSUMPTIONS.md](../formal/ASSUMPTIONS.md)
- [../formal/PROOF_HISTORY.md](../formal/PROOF_HISTORY.md)