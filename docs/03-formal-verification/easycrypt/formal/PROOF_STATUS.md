# Proof Status

Navigation: [EasyCrypt README](../README.md)

## Snapshot

As of May 2026, the EasyCrypt tree under this directory checks cleanly with `./check_easycrypt.sh`, and the repo-local named `axiom` count in `*.ec` files under this directory is `0`.

The active theorem path is therefore fully machine-checked at the current abstraction boundary. The important caveat is that the current boundary is an exact-zero model: the theorem closes because the current MS and LE component budgets are defined as `0%r`, and the active lower surfaces close by exact equality or identity transport.

Alongside that exact-zero path, the tree now also carries a checked semantic-budget theorem path for semantic LE modeling. The intended public citation targets are `qssm_main_theorem` for the exact-zero abstraction theorem and `qssm_main_theorem_semantic_budget` for the semantic-budget theorem; `qssm_main_theorem_nonzero_budget` is a façade alias for discoverability.

## What the `0 axioms` Claim Means

`0 axioms` means there are currently no named `axiom` declarations in the EasyCrypt `*.ec` files under this directory.

It does not mean:

- the formalization is already a realistic nonzero cryptographic security reduction
- every modeling choice has been refined to a final semantic form
- the proof is already linked mechanically to the Rust implementation
- the standard library, checker, or code-to-model correspondence have disappeared as trust boundaries

What has happened is narrower and more precise:

- algebra and sampler closure work moved earlier repo-local assumptions into constructive owners or proved lemmas
- budget names were centralized and then replaced with concrete exact-zero definitions in the current model
- lower rejection and FS surfaces were made concrete enough that the theorem-facing bounds close without in-tree axioms

## Current Theorem-Facing Status

The active theorem stack is checker-green end to end.

- `theorem/MainTheorem.ec` now exposes two public theorem modes: `qssm_main_theorem` is the exact-zero abstraction theorem, and `qssm_main_theorem_semantic_budget` is the preferred semantic-budget theorem closing at `epsilon_le_semantic`
- `qssm_main_theorem_nonzero_budget` is a façade alias to the same semantic theorem, while `qssm_main_theorem_semantic_budget_local_mass`, `qssm_main_theorem_semantic_budget_owned`, and `qssm_main_theorem_semantic_budget_umbrella` are retained for proof history and bisectability
- `theorem/MainTheorem.ec` consumes the MS and LE game-hop chain on the current exact-zero model
- `ms/` closes the MS1, MS2, MS-3a, MS-3b, and MS-3c game-hop surfaces on the current carrier
- `le/` closes the rejection and FS component bounds on the current lower carriers and component budgets
- `games/` packages the MS and LE transition bounds into the final additive theorem path
- `sim/Simulator.ec` closes the public-surface bridge needed for the MS-to-LE handoff

## Budget Models Today

The current budget surface is defined in `primitives/BudgetParameters.ec`.

The exact-zero theorem path uses these values:

- `epsilon_ms_hash_binding = 0%r`
- `epsilon_ms_rom_programmability = 0%r`
- `epsilon_le_rej = 0%r`
- `epsilon_le_fs = 0%r`
- `epsilon_le = epsilon_le_rej + epsilon_le_fs = 0%r`

The parallel semantic-budget theorem path adds these LE-side values:

- `le_rejection_semantic_ticket_category_support = [soft_repair; hard_repair; invalid; accept]`
- `le_rejection_semantic_ticket_category_is_failure category = (category <> accept)`
- primitive rejection slot masses are `soft=1`, `hard=1`, `invalid=1`, `accept=3`
- `d_le_rejection_semantic_branch_slot_choice = duniform (range 0 le_rejection_semantic_total_slot_count)`
- `d_le_rejection_semantic_branch_choice = dmap d_le_rejection_semantic_branch_slot_choice le_rejection_semantic_reject_branch_slot`
- `epsilon_le_rej_semantic = mu1 d_le_rejection_semantic_branch_choice true = le_rejection_semantic_reject_slot_count%r / le_rejection_semantic_total_slot_count%r = 3%r / 6%r = 1%r / 2%r`
- `le_fs_semantic_branch_category_support = [clean; query_collision; programming_collision; transcript_mismatch]`
- `le_fs_semantic_branch_category_is_failure category = (category <> clean)`
- primitive FS slot masses are `clean=3`, `query_collision=1`, `programming_collision=1`, `transcript_mismatch=1`
- `LEFsProgrammingSurface.ec` now interprets the primitive FS categories on a category-coupled shadow state: `clean` is the no-failure/programmed-view branch, `query_collision` is bad-branch query-row alignment, `programming_collision` is bad-branch programmed-response digest/log alignment, and `transcript_mismatch` is bad-branch visible-shell agreement with a cleared semantic bad flag
- `total_slot_count = 6`
- `bad_slot_count = 3`
- `d_le_fs_semantic_branch_slot_choice = duniform (range 0 total_slot_count)`
- `d_le_fs_semantic_branch_choice = dmap d_le_fs_semantic_branch_category_choice le_fs_semantic_branch_category_is_failure`
- `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true = bad_slot_count%r / total_slot_count%r = 3%r / 6%r = 1%r / 2%r`
- `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic = 1%r`

The current theorem-facing results therefore split into two checked modes: an exact-zero bound on the active abstraction theorem path, and a separate semantic-budget theorem path that packages the present semantic rejection plus semantic FS modeling through `epsilon_le_semantic`. The semantic rejection component is now execution-owned below the theorem-facing budget surface, but its probability law remains primitive-owned in `BudgetParameters.ec` with current structured surrogate instantiation `1,1,1,3`, giving `epsilon_le_rej_semantic = 1%r / 2%r`. The semantic FS component is likewise primitive-owned in `BudgetParameters.ec`, and it now has execution-owned meaning in `LEFsProgrammingSurface.ec` rather than only a toy two-slot surrogate view: `clean` is the no-failure/programmed-view branch, while `query_collision`, `programming_collision`, and `transcript_mismatch` each witness a concrete bad-branch condition on the lower shadow state. The local FS bridge still proves equality `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic`, and theorem-facing wrappers then consume the corresponding `<=` bound. The present umbrella therefore evaluates to `1%r` only because both semantic LE subterms are still intentionally loose demo/surrogate laws at the mass level; neither statement should be confused with a final realistic cryptographic reduction for the deployed implementation.

The current semantic FS slot counts are therefore frozen as concrete demo/proof parameters in `primitives/BudgetParameters.ec`. They are not yet sourced from a protocol-parameter bundle, and any future extraction to `primitives/ProtocolParameters.ec` is deferred until there is a real shared protocol parameter surface to centralize.

## What Is Proved on the Live Path

- MS1 hash-binding closes through the current lower probability surface and exact stage equalities.
- MS2 ROM programming closes through the current lower stage equality between the AfterBinding and AfterRom observable laws.
- LE rejection closes on two lower lanes: the active exact-zero rejection lane still collapses to zero on the theorem-facing carrier, while the semantic rejection lane is now execution-owned below the theorem surface and still closes to the owned failure quantity `epsilon_le_rej_semantic = 1%r / 2%r`.
- LE FS closes through the semantic shadow FS lane, whose current failure probability also collapses to zero on the active carrier.
- `LEStatisticalDistance.ec` consumes the rejection and FS component endpoints additively through `epsilon_le = epsilon_le_rej + epsilon_le_fs`.
- `MainTheorem.ec` packages the resulting MS and LE bounds into the final theorem-facing statement, and its semantic theorem path now uses local rejection failure plus local FS bad-branch mass at the comparison level, the owned component sum `epsilon_le_rej_semantic + epsilon_le_fs_semantic`, and the umbrella budget `epsilon_le_semantic`.

## What Is Not Modeled Yet

The following items remain outside the current exact-zero theorem path:

- a non-identity ROM programming model with a nonzero derived MS budget
- a non-identity LE rejection sampler with a nonzero derived rejection budget
- a branch-sensitive, semantically nontrivial LE FS bad-event model on the theorem-facing path
- a nonzero end-to-end quantitative budget connected to realistic lower assumptions
- a machine-checked refinement link from the EasyCrypt model to the Rust implementation

## Current Next Target

The execution-owned semantic rejection-to-FS handoff is now landed and checker-green. `LERealExecution.ec` owns the semantic rejection support/material, `LERejectionSampler.d_le_semantic_post_rejection_view` is the semantic midpoint, `LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view` feeds that midpoint into the semantic FS lane, and `games/GameLEBridge.ec` now packages the resulting semantic projected-simulation advantage without changing the exact-zero theorem path.

The richer execution-owned semantic rejection repair is now also landed and checker-green. `LERealExecution.ec` now carries a semantic rejection decision/ticket together with a repaired reject-branch observable whose hidden query material is brought back into alignment with the repaired visible challenge/programmed-query digests, and the downstream semantic sampler, FS surface, and bridge proofs have all been replayed against that richer surface.

The semantic rejection budget grounding is now also landed and checker-green. `BudgetParameters.epsilon_le_rej_semantic` is now a primitive multi-category ticket-failure probability: `soft_repair`, `hard_repair`, and `invalid` are failure categories, `accept` is the only nonfailure category, and the current surrogate slot masses are `1,1,1,3`, respectively. `LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability` proves that the concrete execution-owned ticket sampler projects to that primitive law, and `LERejectionSampler.le_rejection_shadow_semantic_failure_probability` is now proved equal to that ticket-failure quantity.

The next exact local target is therefore no longer the rejection-owner handoff, the richer repair plumbing, the ticket-failure grounding step itself, or the primitive category split. Semantic count ownership remains intentionally frozen: the current rejection and FS demo/proof counts stay in `primitives/BudgetParameters.ec`, and any `primitives/ProtocolParameters.ec` move remains deferred until there is a real shared protocol-owned source worth centralizing. The next realism step is to keep the same theorem-facing bridge shape while making the current primitive failure categories less surrogate-like than the present `soft/hard/invalid` three-failure-vs-one-accept slot law:

- keep `qssm_main_theorem` as the exact-zero abstraction theorem and `qssm_main_theorem_semantic_budget` as the preferred nonzero citation target
- keep the axiom count at `0`
- keep the current exact-zero theorem path unchanged while refining only the rejection-side lower semantic law, not the current budget owner
- defer any future `primitives/ProtocolParameters.ec` move until there is a real shared parameter source worth centralizing

This is the best next realism step because the semantic rejection owner, semantic post-rejection midpoint, repaired rejection ticket/observable, primitive category law, ticket-failure bridge, semantic FS pre-image, bridge packaging, and semantic umbrella plumbing are now all installed and checker-green; the highest-value local refinement is to make those primitive categories carry richer execution-owned meaning before attempting a richer FS law, MS-side nonzero budgets, or any owner reshuffle.

For the longer-lived trail that led to the current state, see [PROOF_HISTORY.md](PROOF_HISTORY.md).