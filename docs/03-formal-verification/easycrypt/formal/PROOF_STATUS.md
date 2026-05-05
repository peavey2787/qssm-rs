# Proof Status

Navigation: [EasyCrypt README](../README.md)

## Snapshot

As of May 2026, the EasyCrypt tree under this directory checks cleanly with `./check_easycrypt.sh`, and the repo-local named `axiom` count in `*.ec` files under this directory is `0`.

The active theorem path is therefore fully machine-checked at the current abstraction boundary. The important caveat is that the current boundary is an exact-zero model: the theorem closes because the current MS and LE component budgets are defined as `0%r`, and the active lower surfaces close by exact equality or identity transport.

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

- `theorem/MainTheorem.ec` consumes the MS and LE game-hop chain on the current exact-zero model
- `ms/` closes the MS1, MS2, MS-3a, MS-3b, and MS-3c game-hop surfaces on the current carrier
- `le/` closes the rejection and FS component bounds on the current lower carriers and component budgets
- `games/` packages the MS and LE transition bounds into the final additive theorem path
- `sim/Simulator.ec` closes the public-surface bridge needed for the MS-to-LE handoff

## Exact-Zero Budget Model

The current budget surface is defined in `primitives/BudgetParameters.ec`.

The active values are:

- `epsilon_ms_hash_binding = 0%r`
- `epsilon_ms_rom_programmability = 0%r`
- `epsilon_le_rej = 0%r`
- `epsilon_le_fs = 0%r`
- `epsilon_le = epsilon_le_rej + epsilon_le_fs = 0%r`

The current theorem-facing result is therefore an exact-zero bound on the active formal model. That is an honest description of the present development state. It is not a claim that the real system has a nontrivial cryptographic bound of zero gap for the deployed implementation.

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

The next exact local target is the LE FS shadow refinement:

- make the shadow bad-event / failure-probability lane semantically nontrivial
- prove a support-aware good-branch collapse theorem for a branch-sensitive `le_fs_shadow_post_of_observable`
- recover the refined `d_le_fs_shadow_post_marginal_matches_programmed_view` and `d_le_fs_shadow_pre_post_marginals_equal` lemmas
- keep theorem-facing names and global LE arithmetic stable while the lower refinement lands

For the longer-lived trail that led to the current state, see [PROOF_HISTORY.md](PROOF_HISTORY.md).