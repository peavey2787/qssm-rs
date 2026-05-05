# Proof Status

Navigation: [EasyCrypt README](../README.md)

## Snapshot

As of May 2026, the EasyCrypt tree under this directory checks cleanly with `./check_easycrypt.sh`, and the repo-local named `axiom` count in `*.ec` files under this directory is `0`.

The active theorem path is therefore fully machine-checked at the current abstraction boundary. The important caveat is that the current boundary is an exact-zero model: the theorem closes because the current MS and LE component budgets are defined as `0%r`, and the active lower surfaces close by exact equality or identity transport.

Alongside that exact-zero path, the tree now also carries a checked semantic-budget theorem path for nonzero LE FS modeling. The intended public citation targets are `qssm_main_theorem` for the exact-zero abstraction theorem and `qssm_main_theorem_semantic_budget` for the semantic-budget theorem; `qssm_main_theorem_nonzero_budget` is a façade alias for discoverability.

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

- `d_le_fs_semantic_branch_choice = duniform [false; true]`
- `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true = 1%r / 2%r`
- `epsilon_le_semantic = epsilon_le_rej + epsilon_le_fs_semantic = 1%r / 2%r`

The current theorem-facing results therefore split into two checked modes: an exact-zero bound on the active abstraction theorem path, and a separate semantic-budget theorem path that packages the present nonzero LE FS modeling through `epsilon_le_semantic`. The semantic FS component is now primitive-owned as a branch-weight formula rather than a bare literal, even though it still evaluates in the current model to `1%r / 2%r`. Neither statement should be confused with a final realistic cryptographic reduction for the deployed implementation.

## What Is Proved on the Live Path

- MS1 hash-binding closes through the current lower probability surface and exact stage equalities.
- MS2 ROM programming closes through the current lower stage equality between the AfterBinding and AfterRom observable laws.
- LE rejection closes through the semantic shadow rejection lane, whose current failure probability collapses to zero on the active carrier.
- LE FS closes through the semantic shadow FS lane, whose current failure probability also collapses to zero on the active carrier.
- `LEStatisticalDistance.ec` consumes the rejection and FS component endpoints additively through `epsilon_le = epsilon_le_rej + epsilon_le_fs`.
- `MainTheorem.ec` packages the resulting MS and LE bounds into the final theorem-facing statement.

## What Is Not Modeled Yet

The following items remain outside the current exact-zero theorem path:

- a non-identity ROM programming model with a nonzero derived MS budget
- a non-identity LE rejection sampler with a nonzero derived rejection budget
- a branch-sensitive, semantically nontrivial LE FS bad-event model on the theorem-facing path
- a nonzero end-to-end quantitative budget connected to realistic lower assumptions
- a machine-checked refinement link from the EasyCrypt model to the Rust implementation

## Current Next Target

The next exact local target is to refine the semantic-budget lane below the now-stable public theorem API:

- replace the current toy semantic FS component budget with a more realistic lower-derived quantity or explicit programming expression
- keep `qssm_main_theorem` as the exact-zero abstraction theorem and `qssm_main_theorem_semantic_budget` as the preferred nonzero citation target
- decide later whether the retained comparison lemmas should remain exported or move behind a narrower compatibility surface

For the longer-lived trail that led to the current state, see [PROOF_HISTORY.md](PROOF_HISTORY.md).