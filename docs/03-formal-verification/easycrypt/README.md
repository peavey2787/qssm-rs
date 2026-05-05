# EasyCrypt Formalization

This directory contains the EasyCrypt proof development for the QSSM theorem stack. It includes the theorem-facing MS, LE, simulator, game, and main-theorem layers, together with the lower proof surfaces used to stage constructive refinements before they are routed into the stable theorem path.

Current status: the tree checks cleanly with `./check_easycrypt.sh`, the repo-local named `axiom` count in `*.ec` files under this directory is currently `0`, and the active theorem path closes on a concrete exact-zero budget model. That is a machine-checked statement about the current abstraction boundary, not yet a nonzero cryptographic security estimate for the deployed system.

The main live refinement track is the LE shadow lane. Rejection and FS theorem-facing component bounds already route through lower shadow surfaces, but the active FS bad-event lane is still exact-zero on the current model. The next missing local result is a support-aware good-branch collapse theorem for a branch-sensitive shadow post constructor.

## What This Directory Covers

- EasyCrypt theories under `primitives/`, `ms/`, `le/`, `sim/`, `games/`, and `theorem/`
- The checked QSSM theorem skeleton and its lower proof surfaces
- Architecture, status, and proof-history documentation for the current May 2026 state
- No direct Rust implementation changes; this tree is the formal model and proof development

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
- [formal/LE_REFINEMENT_PLAN.md](formal/LE_REFINEMENT_PLAN.md): current shadow-lane plan for non-identity LE rejection / FS semantics and future budget restoration

Related planning notes:

- [plans/LE_HVZK_proof_plan.md](plans/LE_HVZK_proof_plan.md)
- [plans/MS_3c_proof_plan.md](plans/MS_3c_proof_plan.md)

## Current Truth in One View

- The EasyCrypt tree is checker-green today.
- Repo-local named axioms in `*.ec` files under this directory are currently at `0`.
- The active theorem path is exact-zero because the current budget model sets the MS and LE component budgets to `0%r` and the lower proof lanes close by exact distribution equality or identity transport.
- The proof stack is therefore machine-checked as a formal scaffold with concrete lower carriers, not yet as a nonzero end-to-end cryptographic bound.
- The next meaningful refinement remains the LE FS shadow lane, not another round of README expansion.