# EasyCrypt Formalization

This directory contains the EasyCrypt proof development for the QSSM theorem stack. It includes the theorem-facing MS, LE, simulator, game, and main-theorem layers, together with the lower proof surfaces used to stage constructive refinements before they are routed into the stable theorem path.

Current status: the tree checks cleanly with `./check_easycrypt.sh`, the repo-local named `axiom` count in `*.ec` files under this directory is currently `0`, and the active theorem path closes on a concrete exact-zero budget model. That is a machine-checked statement about the current abstraction boundary, not yet a nonzero cryptographic security estimate for the deployed system.

The main live refinement track is the LE shadow lane. Rejection and FS theorem-facing component bounds already route through lower shadow surfaces, and the branch-sensitive FS shadow post constructor is now landed and checker-validated on the current exact-zero model. The lower FS surface now splits into two internal lanes. The exported projected-post lane still proves the theorem-facing bridge theorems consumed by `LEFsProgramming.ec`, keeps the active FS endpoint unchanged, and still closes with `epsilon_le_fs = 0%r`. Beside it, `LEFsProgrammingSurface.ec` now carries a shadow-local semantic branch experiment with a genuine two-branch good/bad sampler, semantic post marginal, and local bad-branch mass that closes in owned form to `epsilon_le_fs_semantic = bad_slot_count%r / total_slot_count%r = 1%r / 2%r`. The rejection shadow lane now likewise splits into two checked modes: the exact-zero theorem-facing quantity `LERejectionSampler.le_rejection_shadow_failure_probability` still closes to `0%r`, while the semantic rejection quantity `LERejectionSampler.le_rejection_shadow_semantic_failure_probability` closes to the owned budget `epsilon_le_rej_semantic = mu1 d_le_rejection_semantic_branch_choice true = 1%r / 4%r`. The semantic rejection owner is now execution-owned below the theorem surface: `LERealExecution.ec` owns the semantic rejection branch support and branch-dependent material, `LERejectionSampler.ec` exports `d_le_semantic_post_rejection_view`, and `LEFsProgrammingSurface.ec` now feeds that semantic post-rejection view into `d_le_pre_fs_semantic_programming_view` and `d_le_post_fs_semantic_programmed_view`, so the semantic FS lane is no longer fed by a parallel-only rejection experiment term. `BudgetParameters.ec` still owns both semantic branch weights via concrete demo/proof counts: the rejection lane uses `le_rejection_semantic_total_slot_count = 4` and `le_rejection_semantic_reject_slot_count = 1`, while the FS lane keeps `total_slot_count = 4` and `bad_slot_count = 2`. Those counts are intentionally concrete demo/proof parameters for the current semantic experiments, not values sourced from a protocol-parameter bundle. The semantic umbrella LE budget now uses both semantic components, so `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic = 3%r / 4%r`. `LERejectionSampler.ec` proves the semantic rejection lane closes to its owned budget, `LEFsProgrammingSurface.ec` proves the local FS bad-branch mass equals the owned FS budget, `GameLEBridge.ec` now bridges the semantic projected-simulation advantage over that execution-owned rejection-to-FS chain, and the theorem-facing semantic chain closes both at the local-mass level and at the owned component-sum / umbrella levels. The public theorem surface is now normalized: cite `qssm_main_theorem` for the exact-zero abstraction theorem, and cite `qssm_main_theorem_semantic_budget` for the semantic-budget theorem. `qssm_main_theorem_nonzero_budget` is a façade alias to the same semantic umbrella theorem, while `qssm_main_theorem_semantic_budget_local_mass`, `qssm_main_theorem_semantic_budget_owned`, and `qssm_main_theorem_semantic_budget_umbrella` are retained as comparison or compatibility lemmas. `A_G1_to_G2_le_transition_bound` and `qssm_main_theorem_skeleton` remain unchanged, so the exact-zero model stays live beside the semantic budget path.

## What This Directory Covers

- EasyCrypt theories under `primitives/`, `ms/`, `le/`, `sim/`, `games/`, and `theorem/`
- The checked QSSM theorem skeleton and its lower proof surfaces
- Architecture, status, and proof-history documentation for the current May 2026 state
- No direct Rust implementation changes; this tree is the formal model and proof development

## Verification Boundary

- The current proof closes on a concrete exact-zero model, not yet on a nonzero cryptographic reduction.
- There is no machine-checked refinement link from these EasyCrypt theories to the Rust implementation today.
- Correctness of the EasyCrypt checker, the imported foundations, and the human model-to-implementation correspondence remain external trust boundaries.
- The exact meaning of the current `0 axioms` and `0%r` budget state is documented in [formal/PROOF_STATUS.md](formal/PROOF_STATUS.md) and [formal/ASSUMPTIONS.md](formal/ASSUMPTIONS.md).

## Install EasyCrypt

If `easycrypt` is not already in `PATH`, install it with OPAM using the upstream instructions:

- [EasyCrypt INSTALL.md](https://github.com/EasyCrypt/easycrypt/blob/main/INSTALL.md)
- [Setting up EasyCrypt](https://easycrypt.gitlab.io/easycrypt-web/docs/guides/setting-up-easycrypt/)

If your installation exposes the binary as `ec` instead of `easycrypt`, the local checker script falls back automatically.

The repo-local import allowlist is in [../easycrypt-import-allowlist.md](../easycrypt-import-allowlist.md).

## How to Run the Checker

From this directory:

```bash
chmod +x check_easycrypt.sh   # once, if needed
./check_easycrypt.sh
```

Or with an explicit binary path:

```bash
EASYCRYPT=/path/to/easycrypt ./check_easycrypt.sh
```

The script type-checks theories in dependency order with `easycrypt compile -R . <path>`, so imports resolve by basename. The compile-order authority is [check_easycrypt.sh](check_easycrypt.sh); if any prose summary disagrees with the script, follow the script.

To inspect the current load order directly:

```bash
sed -n '/^FILES=(/,/^)/p' check_easycrypt.sh
```

Single-file top-of-stack check:

```bash
easycrypt compile -R . theorem/MainTheorem.ec
```

## Architecture Summary

High-level dependency flow:

```text
primitives/
  -> ms/ foundations, source, true-clause, comparison, wrapper
  -> le/ real-execution, rejection, FS, HVZK
ms/ + le/ -> sim/
ms/ + le/ + sim/ -> games/
games/ -> theorem/MainTheorem.ec
```

Operationally:

- `primitives/` owns shared domains, types, algebra, Fiat-Shamir surface, and budget parameters.
- `ms/` carries the MS proof stack, including the split MS-3a, MS-3b, and MS-3c surfaces.
- `le/` carries the LE real-execution, rejection, FS-programming, and HVZK stack.
- `sim/Simulator.ec` bridges the MS public surface into the LE-facing real view.
- `games/` packages the game views, advantage arithmetic, MS hops, and LE bridge.
- `theorem/MainTheorem.ec` is the top-level additive theorem layer.

Stable theorem-facing facades include:

- `ms/TrueClause.ec`
- `ms/Comparison.ec`
- `ms/SourceModel.ec`
- `ms/MS.ec`
- `le/LEModel.ec`
- `games/Games.ec`
- `theorem/MainTheorem.ec`

Split-heavy subtree guides live in:

- [ms/source/README.md](ms/source/README.md)
- [ms/comparison/README.md](ms/comparison/README.md)
- [games/README.md](games/README.md)

The deeper architecture and file-map material moved to [formal/ARCHITECTURE.md](formal/ARCHITECTURE.md).

## Documentation Map

- [formal/PROOF_STATUS.md](formal/PROOF_STATUS.md): current theorem status, checker state, and the exact meaning of the `0 axioms` claim
- [formal/ASSUMPTIONS.md](formal/ASSUMPTIONS.md): current model boundary, budget semantics, and what remains intentionally exact-zero
- [formal/ARCHITECTURE.md](formal/ARCHITECTURE.md): module breakdown, dependency flow, directory structure, and legacy file map
- [formal/PROOF_HISTORY.md](formal/PROOF_HISTORY.md): preserved May 2026 audit log, closure notes, and long-form research history moved out of this entrypoint

## Plan Index

- [plans/G0_G1_G2_game_plan.md](plans/G0_G1_G2_game_plan.md): top-level `G0 -> G1 -> G2` game-hop composition plan
- [plans/LE_HVZK_proof_plan.md](plans/LE_HVZK_proof_plan.md): LE HVZK decomposition, obligation map, and theorem-path packaging notes
- [plans/LE_REFINEMENT_PLAN.md](plans/LE_REFINEMENT_PLAN.md): next-stage LE rejection / FS shadow refinement plan
- [plans/MS_3a_proof_plan.md](plans/MS_3a_proof_plan.md): MS-3a exact bitness-simulation plan and residual lower-layer debt
- [plans/MS_3b_proof_plan.md](plans/MS_3b_proof_plan.md): MS-3b true-clause / highest-differing-bit characterization plan
- [plans/MS_3c_proof_plan.md](plans/MS_3c_proof_plan.md): MS-3c comparison-lane plan and game-boundary closure history
- [plans/MS_3d_proof_plan.md](plans/MS_3d_proof_plan.md): post-MS-3c MS game-layer cleanup and residual budget-facing work

Every plan file and local subtree guide linked from this README includes a return link back here.

## Current Truth in One View

- The EasyCrypt tree is checker-green today.
- Repo-local named axioms in `*.ec` files under this directory are currently at `0`.
- The active theorem path is exact-zero because the current budget model sets the MS and LE component budgets to `0%r` and the lower proof lanes close by exact distribution equality or identity transport.
- The LE FS shadow surface now has two checker-validated internal lanes: an exported projected-post lane that still proves the theorem-facing zero-budget bridge lemmas, and a separate shadow-local semantic branch experiment with a genuine two-branch good/bad sampler. On that local semantic lane, the good branch image is exactly the theorem-facing programmed view, the bad branch image is a separate semantic programmed post view, the semantic-post marginal is the branch-choice pushforward over those two images, and its `sdist` from the theorem-facing programmed view is locally bounded by `le_fs_shadow_local_bad_branch_mass = bad_slot_count%r / total_slot_count%r`, which instantiates in the current model to `1%r / 2%r`. `BudgetParameters.ec` now owns the corresponding primitive branch-weight formula `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true`, where `total_slot_count = 4`, `bad_slot_count = 2`, `d_le_fs_semantic_branch_slot_choice = duniform (range 0 total_slot_count)`, and `d_le_fs_semantic_branch_choice = dmap d_le_fs_semantic_branch_slot_choice le_fs_semantic_bad_branch_slot`; `LEFsProgrammingSurface.ec` proves `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic` and that same owned quantity still closes to `1%r / 2%r` in the current model.
- Two public theorem modes are now present. Cite `qssm_main_theorem` for the exact-zero abstraction theorem. Cite `qssm_main_theorem_semantic_budget` for the nonzero semantic-budget theorem; `qssm_main_theorem_nonzero_budget` is a synonym for discoverability. The retained comparison variants are `qssm_main_theorem_semantic_budget_local_mass`, `qssm_main_theorem_semantic_budget_owned`, and `qssm_main_theorem_semantic_budget_umbrella`.
- The proof stack is therefore machine-checked as a formal scaffold with concrete lower carriers, not yet as a nonzero end-to-end cryptographic bound.
- The active exact-zero route is still unchanged: `epsilon_le_fs` and `epsilon_le` remain `0%r`, `A_G1_to_G2_le_transition_bound` still closes on `epsilon_le`, and `qssm_main_theorem` still rewrites all the way down to `<= 0%r`.
- The semantic FS demo-count owner is intentionally frozen for now: `total_slot_count` and `bad_slot_count` remain concrete proof/demo parameters in `BudgetParameters.ec`, not a protocol bundle, and any later move to `primitives/ProtocolParameters.ec` is deferred until a real shared parameter source exists.
- The semantic rejection lane is now execution-owned below the theorem surface: `LERealExecution.ec` owns the rejection branch/material, `LERejectionSampler.d_le_semantic_post_rejection_view` is the semantic midpoint, and `LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view` plus `d_le_post_fs_semantic_programmed_view` now feed that midpoint into the semantic FS lane while the exact-zero rejection route remains unchanged.
- The next meaningful modeling refinement is no longer the rejection-owner handoff; that handoff is now complete. The next realism step is to replace the current concrete semantic demo/proof branch counts with a more protocol-owned or otherwise richer source without disturbing the exact-zero theorem path or the public theorem names.