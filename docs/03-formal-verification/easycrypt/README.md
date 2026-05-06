# EasyCrypt Formalization

This directory contains the EasyCrypt proof development for the QSSM theorem stack. It includes the theorem-facing MS, LE, simulator, game, and main-theorem layers, together with the lower proof surfaces used to stage constructive refinements before they are routed into the stable theorem path.

Current status: the tree checks cleanly with `./check_easycrypt.sh`, the repo-local named `axiom` count in `*.ec` files under this directory is currently `0`, and the active theorem path closes on a concrete exact-zero budget model. That is a machine-checked statement about the current abstraction boundary, not yet a nonzero cryptographic security estimate for the deployed system.

The main live refinement track is the LE shadow lane. Rejection and FS theorem-facing component bounds already route through lower shadow surfaces, and the branch-sensitive FS shadow post constructor is now landed and checker-validated on the current exact-zero model. The lower FS surface now splits into two internal lanes. The exported projected-post lane still proves the theorem-facing bridge theorems consumed by `LEFsProgramming.ec`, keeps the active FS endpoint unchanged, and still closes with `epsilon_le_fs = 0%r`. Beside it, `LEFsProgrammingSurface.ec` now carries a shadow-local semantic branch experiment with a genuine two-branch good/bad sampler, semantic post marginal, and local bad-branch mass that closes in owned form to `epsilon_le_fs_semantic = le_fs_failure_slot_count%r / le_fs_total_slot_count%r = 3%r / 16%r`. The rejection shadow lane now likewise splits into two checked modes: the exact-zero theorem-facing quantity `LERejectionSampler.le_rejection_shadow_failure_probability` still closes to `0%r`, while the semantic rejection quantity `LERejectionSampler.le_rejection_shadow_semantic_failure_probability` closes to the owned budget `epsilon_le_rej_semantic = le_rejection_semantic_ticket_failure_probability = le_rej_failure_slot_count%r / le_rej_total_slot_count%r = 3%r / 16%r`. `BudgetParameters.ec` owns both primitive semantic LE laws and now also a parallel primitive MS ROM semantic skeleton: rejection uses the category support `soft_repair`, `hard_repair`, `invalid`, `accept`, failure predicate “non-accept”, and the named count constants `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`, `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`, `le_rej_failure_slot_count`, and `le_rej_total_slot_count`; FS uses the category support `clean`, `query_collision`, `programming_collision`, `transcript_mismatch`, failure predicate “non-clean”, and the named count constants `le_fs_clean_slot_count`, `le_fs_query_collision_slot_count`, `le_fs_programming_collision_slot_count`, `le_fs_transcript_mismatch_slot_count`, `le_fs_failure_slot_count`, and `le_fs_total_slot_count`; MS ROM now mirrors that category shape with `ms_rom_semantic_category_support`, `ms_rom_semantic_category_is_failure`, the named counts `ms_rom_clean_slot_count`, `ms_rom_query_collision_slot_count`, `ms_rom_programming_collision_slot_count`, `ms_rom_transcript_mismatch_slot_count`, `ms_rom_failure_slot_count`, and `ms_rom_total_slot_count`, and the parallel owner term `epsilon_ms_rom_programmability_semantic = ms_rom_failure_slot_count%r / ms_rom_total_slot_count%r = 3%r / 16%r`. `primitives/FS.ec` now re-exports that semantic MS ROM owner as `epsilon_ms_rom_programmability_semantic` together with the nonnegativity lemma `A2_ms_rom_programmability_semantic_nonneg`, and the lower/game MS2 route now also carries the semantic sibling chain `A_MS2_rom_programming_semantic_transition_bound`, `A_MS2_rom_programming_semantic_game_pr_core_bound`, `A_MS2_rom_programming_semantic_concrete_pair_advantage_bound`, `A_MS2_canonical_rom_programming_semantic_bound`, `A_MS2_rom_programming_semantic_transition`, and `A_G0_to_G1_ms_semantic_transition_bound`, each closing against `epsilon_ms_rom_programmability_semantic`. The current rejection demo instance is `soft_repair=1`, `hard_repair=1`, `invalid=1`, and `accept=13`, so `le_rej_failure_slot_count = 3` and `le_rej_total_slot_count = 16`; the compatibility aliases `le_rejection_semantic_reject_slot_count` and `le_rejection_semantic_total_slot_count` remain preserved for the downstream rejection bridge surface. The current FS demo instance is `clean=13`, `query_collision=1`, `programming_collision=1`, and `transcript_mismatch=1`, so `le_fs_failure_slot_count = 3` and `le_fs_total_slot_count = 16`; the compatibility aliases `bad_slot_count` and `total_slot_count` remain preserved for the downstream bridge surface. The current MS ROM semantic demo instance is `clean=13`, `query_collision=1`, `programming_collision=1`, and `transcript_mismatch=1`, so `ms_rom_failure_slot_count = 3` and `ms_rom_total_slot_count = 16`, and `theorem/MainTheorem.ec` now routes the semantic theorem variants through `A_G0_to_G1_ms_semantic_transition_bound`, so the semantic top-level path adds `epsilon_ms_rom_programmability_semantic` while the exact-zero `qssm_main_theorem_skeleton` / `qssm_main_theorem` route still consumes `epsilon_ms_rom_programmability = 0%r`. `LERealExecution.ec` only interprets the primitive rejection categories into the existing reject/repair surface, `LERejectionSampler.ec` exports `d_le_semantic_post_rejection_view`, and `LEFsProgrammingSurface.ec` feeds that semantic post-rejection view into `d_le_pre_fs_semantic_programming_view` and `d_le_post_fs_semantic_programmed_view`, now interpreting the primitive FS categories on a category-coupled shadow state. The exact lower names are `d_le_fs_shadow_category_choice`, `le_fs_shadow_state_of_category_observable`, `le_fs_shadow_clean_condition`, `le_fs_shadow_query_collision_condition`, `le_fs_shadow_programming_collision_condition`, `le_fs_shadow_transcript_mismatch_condition`, and the witness lemmas `le_fs_shadow_clean_condition_clean_categoryE`, `le_fs_shadow_query_collision_condition_query_collision_categoryE`, `le_fs_shadow_programming_collision_condition_programming_collision_categoryE`, `le_fs_shadow_transcript_mismatch_condition_transcript_mismatch_categoryE`, and `le_fs_shadow_semantic_category_condition_stateE`. On the lower rejection lane, `LERealExecution.ec` gives the semantic ticket categories their execution-owned interpretation while `LERejectionSampler.ec` preserves the exact bridge to `epsilon_le_rej_semantic`; on the lower FS lane, `clean` is the no-failure branch whose semantic post observable collapses to the theorem-facing programmed view, `query_collision` witnesses bad-branch query-row alignment, `programming_collision` witnesses bad-branch programmed-response digest/log alignment, and `transcript_mismatch` witnesses bad-branch visible-shell agreement with a cleared semantic bad flag. The preserved compatibility views still export the derived boolean bad-branch images, so the theorem-facing wrappers remain unchanged. Both semantic LE subterms are still intentionally loose demo/surrogate laws at the mass level in `BudgetParameters.ec`, even though the rejection and FS categories now have execution-owned meanings below the theorem surface. The semantic umbrella LE budget therefore currently evaluates to `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic = 3%r / 8%r`, and that value should not be read as a final cryptographic reduction. The MS semantic owners are likewise primitive surrogate laws today: the retargeted live semantic MainTheorem path now closes at `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic + epsilon_le_semantic = 3%r / 16%r + 3%r / 16%r + 3%r / 8%r = 3%r / 4%r`, `ms/MSProbabilitySurface.ec` now also defines the semantic AfterRom endpoint `d_ms_after_rom_semantic_observable_v2` from `d_ms_rom_semantic_coupled_state` through the bridge projection `ms_rom_semantic_after_rom_observable_of_state`, proves the non-identity local lemma `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure`, and still closes `A_MS2_rom_programming_semantic_transition_bound` against the strengthened execution-owned divergence bridge `A_MS2_rom_programming_execution_owned_semantic_bound` while the exact-zero `A_MS2_rom_programming_transition_bound` stays unchanged. `games/GameMSHopComposition.ec : A_G0_to_G1_ms_semantic_transition_bound` plus the semantic `theorem/MainTheorem.ec` route therefore continue to consume the full-MS semantic path without any routing change. `LERejectionSampler.ec` proves the semantic rejection lane closes to its owned budget, `LEFsProgrammingSurface.ec` proves the local FS bad-branch mass equals the owned FS budget, `GameLEBridge.ec` bridges the semantic projected-simulation advantage over that execution-owned rejection-to-FS chain, and the theorem-facing semantic chain closes both at the local-mass level and at the owned component-sum / umbrella levels. The public theorem surface is now normalized: cite `qssm_main_theorem` for the exact-zero abstraction theorem, and cite `qssm_main_theorem_semantic_budget` for the semantic-budget theorem. `qssm_main_theorem_nonzero_budget` is a façade alias to the same semantic umbrella theorem, while `qssm_main_theorem_semantic_budget_local_mass`, `qssm_main_theorem_semantic_budget_owned`, and `qssm_main_theorem_semantic_budget_umbrella` are retained as comparison or compatibility lemmas. `A_G1_to_G2_le_transition_bound` and `qssm_main_theorem_skeleton` remain unchanged, so the exact-zero model stays live beside the semantic budget path.

`BudgetParameters.ec` now also carries a parallel semantic MS1 hash-binding owner skeleton beside the live theorem route. Its category support is `clean`, `collision`, `malformed_binding`, and `transcript_mismatch`; the current demo counts are `13,1,1,1`, so `ms_hash_binding_failure_slot_count = 3`, `ms_hash_binding_total_slot_count = 16`, and `epsilon_ms_hash_binding_semantic = 3%r / 16%r`. `primitives/FS.ec` re-exports that owner, `ms/MS.ec` now adds the staged MS-side alias/nonneg surface, and `ms/source/SourceHashBindingSemanticBridge.ec` now gives the term a source-local execution-owned bridge with the staged sibling chain `A_MS1_hash_binding_semantic_bad_event_bound`, `A_MS1_hash_binding_semantic_game_pr_core_bound`, `A_MS1_hash_binding_semantic_concrete_pair_advantage_bound`, `A_MS1_canonical_hash_binding_semantic_bound`, `A_MS1_hash_binding_semantic_transition`, and `A_G0_to_G1_ms_hash_binding_semantic_transition_bound`. The staged sibling remains present, and the live semantic theorem route now also consumes semantic MS1: `games/GameMSHopComposition.ec : A_G0_to_G1_ms_semantic_transition_bound` and the semantic variants in `theorem/MainTheorem.ec` now consume `epsilon_ms_hash_binding_semantic`, so the current semantic top formula is `epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic + epsilon_le_semantic = 3%r / 4%r`. The exact-zero `qssm_main_theorem_skeleton` / `qssm_main_theorem` route still consumes `epsilon_ms_hash_binding = 0%r`.

The MS ROM gap is now narrower than before. `ms/comparison/ComparisonPayloadSemanticBridge.ec` now gives the semantic owner a comparison-local execution-owned bridge surface: it defines `ms_rom_semantic_state_of_category_execution_seed`, the category predicates `ms_rom_clean_condition`, `ms_rom_query_collision_condition`, `ms_rom_programming_collision_condition`, `ms_rom_transcript_mismatch_condition`, the local mass `ms_rom_local_failure_mass`, the semantic AfterRom projection `ms_rom_semantic_after_rom_observable_of_state`, and the lower bound `A_MS2_rom_programming_execution_owned_semantic_bound`. That bridge is checker-green, included in `./check_easycrypt.sh`, and is now consumed locally by `ms/MSProbabilitySurface.ec` both through the semantic endpoint `d_ms_after_rom_semantic_observable_v2` and through the semantic lower bound `L_ms2_rom_programming_transition_le_execution_owned_semantic_failure`, while the exact-zero MS2 stage route remains unchanged. Since then, `games/GameMSHopComposition.ec : A_G0_to_G1_ms_semantic_transition_bound` and the semantic `theorem/MainTheorem.ec` route have been retargeted to the full-MS semantic composition, while the exact-zero route remains unchanged.

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
- [formal/ARCHITECTURE.md](formal/ARCHITECTURE.md): module breakdown, dependency flow, directory structure
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
- The LE FS shadow surface now has two checker-validated internal lanes: an exported projected-post lane that still proves the theorem-facing zero-budget bridge lemmas, and a separate shadow-local semantic branch experiment with a genuine good/bad branch split. On that local semantic lane, the good branch image is exactly the theorem-facing programmed view, the bad branch image is a separate semantic programmed post view, the semantic-post marginal is the branch-choice pushforward over those two images, and its `sdist` from the theorem-facing programmed view is locally bounded by `le_fs_shadow_local_bad_branch_mass`. `BudgetParameters.ec` now owns the corresponding primitive structured FS category law with support `clean`, `query_collision`, `programming_collision`, `transcript_mismatch`, failure predicate “non-clean”, and named count constants `le_fs_clean_slot_count`, `le_fs_query_collision_slot_count`, `le_fs_programming_collision_slot_count`, `le_fs_transcript_mismatch_slot_count`, `le_fs_failure_slot_count`, and `le_fs_total_slot_count`. The current demo instance is `clean=13`, `query_collision=1`, `programming_collision=1`, and `transcript_mismatch=1`, so `le_fs_failure_slot_count = 3` and `le_fs_total_slot_count = 16`; the compatibility aliases `bad_slot_count` and `total_slot_count` remain in place. The exact interpretation ops are `d_le_fs_shadow_category_choice`, `le_fs_shadow_state_of_category_observable`, `le_fs_shadow_clean_condition`, `le_fs_shadow_query_collision_condition`, `le_fs_shadow_programming_collision_condition`, and `le_fs_shadow_transcript_mismatch_condition`. The category witness lemmas are `le_fs_shadow_clean_condition_clean_categoryE`, `le_fs_shadow_query_collision_condition_query_collision_categoryE`, `le_fs_shadow_programming_collision_condition_programming_collision_categoryE`, `le_fs_shadow_transcript_mismatch_condition_transcript_mismatch_categoryE`, and `le_fs_shadow_semantic_category_condition_stateE`. `LEFsProgrammingSurface.ec` now interprets those primitive categories on a category-coupled shadow state: `clean` is the no-failure/programmed-view branch, `query_collision` is bad-branch query-row alignment, `programming_collision` is bad-branch programmed-response digest/log alignment, and `transcript_mismatch` is bad-branch visible-shell agreement with a cleared semantic bad flag. The preserved compatibility view still exports `d_le_fs_semantic_branch_choice` as the derived boolean bad-branch image and keeps `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true = le_fs_failure_slot_count%r / le_fs_total_slot_count%r`, which therefore now closes to `3%r / 16%r` in the current model. `LEFsProgrammingSurface.ec` proves the local equality `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic`, while theorem-facing wrappers consume the corresponding `<=` bound.
- Two public theorem modes are now present. Cite `qssm_main_theorem` for the exact-zero abstraction theorem. Cite `qssm_main_theorem_semantic_budget` for the nonzero semantic-budget theorem; `qssm_main_theorem_nonzero_budget` is a synonym for discoverability. The retained comparison variants are `qssm_main_theorem_semantic_budget_local_mass`, `qssm_main_theorem_semantic_budget_owned`, and `qssm_main_theorem_semantic_budget_umbrella`.
- The proof stack is therefore machine-checked as a formal scaffold with concrete lower carriers, not yet as a nonzero end-to-end cryptographic bound.
- The active exact-zero route is still unchanged: `epsilon_le_fs` and `epsilon_le` remain `0%r`, `A_G1_to_G2_le_transition_bound` still closes on `epsilon_le`, and `qssm_main_theorem` still rewrites all the way down to `<= 0%r`.
- The semantic FS demo-count owner is intentionally frozen for now: the canonical owner count names in `BudgetParameters.ec` are `le_fs_clean_slot_count`, `le_fs_query_collision_slot_count`, `le_fs_programming_collision_slot_count`, `le_fs_transcript_mismatch_slot_count`, `le_fs_failure_slot_count`, and `le_fs_total_slot_count`, while `total_slot_count` and `bad_slot_count` remain preserved compatibility aliases for the downstream bridge surface. Any later move to `primitives/ProtocolParameters.ec` is deferred until a real shared parameter source exists.
- The semantic rejection lane is now execution-owned below the theorem surface: `LERealExecution.ec` owns the rejection branch/material, `LERejectionSampler.d_le_semantic_post_rejection_view` is the semantic midpoint, and `LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view` plus `d_le_post_fs_semantic_programmed_view` now feed that midpoint into the semantic FS lane while the exact-zero rejection route remains unchanged.
- The richer execution-owned semantic rejection repair is now landed: `LERealExecution.ec` now carries a semantic rejection decision/ticket and a repaired reject-branch observable whose hidden query material is realigned with the repaired visible challenge/programmed-query digests, while `LERejectionSampler.ec`, `LEFsProgrammingSurface.ec`, and `games/GameLEBridge.ec` replay that richer surface without changing the exact-zero route or the public theorem names.
- The public semantic rejection budget is now grounded in a primitive multi-category ticket-failure law rather than a single boolean repair slot: `BudgetParameters.ec` now samples primitive ticket categories `soft_repair`, `hard_repair`, `invalid`, and `accept`, treats every non-`accept` category as failure, and owns the resulting rejection mass law through `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`, `le_rej_invalid_slot_count`, `le_rej_accept_slot_count`, `le_rej_failure_slot_count`, and `le_rej_total_slot_count`. The current demo instance is `1,1,1,13`, so `le_rej_failure_slot_count = 3` and `le_rej_total_slot_count = 16`, while the preserved aliases `le_rejection_semantic_reject_slot_count` and `le_rejection_semantic_total_slot_count` keep the bridge surface unchanged. `LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability` proves the concrete execution-owned ticket sampler matches that primitive law, and `LERejectionSampler.le_rejection_shadow_semantic_failure_probability` is now proved equal to that ticket-failure quantity. The current theorem-facing budget therefore closes to `epsilon_le_rej_semantic = le_rej_failure_slot_count%r / le_rej_total_slot_count%r = 3%r / 16%r`, while the exact-zero route remains unchanged. The next meaningful modeling refinement is still not a theorem-surface move; with both rejection and FS semantic counts now parameterized under stable owner names in `BudgetParameters.ec`, the remaining local target is to protocol-source or otherwise justify those counts without changing the theorem API.