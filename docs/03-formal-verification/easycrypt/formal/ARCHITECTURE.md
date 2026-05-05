# Architecture

## Purpose

This document is the deep-structure companion to the root README. It explains how the EasyCrypt tree is split, which files act as stable facades, and where the lower proof surfaces live.

## Dependency Flow

The conceptual load order is:

1. `primitives/` — shared domains, types, algebra, Fiat-Shamir surface, and budgets
2. `ms/` foundations — Schnorr single-branch, bitness, transcript observable, and split MS layers
3. `ms/true_clause/` — MS-3b leaf chain behind `ms/TrueClause.ec`
4. `ms/comparison/` — MS-3c leaf chain behind `ms/Comparison.ec`
5. `ms/SourceModel.ec` and `ms/source/` — MS-3a public-spine / source-model lane
6. `ms/MS.ec` — theorem-facing MS wrapper
7. `le/` — LE real-execution, rejection, FS-programming, statistical-distance, and HVZK stack
8. `sim/Simulator.ec` — simulator bridge over the MS and LE layers
9. `games/` — game views, advantage arithmetic, MS hops, and LE bridge
10. `theorem/MainTheorem.ec` — final theorem-facing composition

The exact compile order is owned by [../check_easycrypt.sh](../check_easycrypt.sh). Treat the script as authoritative if this prose ever drifts.

## High-Level Diagram

```text
                    primitives/
                  /             \
               ms/               le/
                 \               /
                  \             /
                   sim/Simulator.ec
                          |
                        games/
                          |
                theorem/MainTheorem.ec
```

## Module Roles

### `primitives/`

Owns the shared low-level carriers and interfaces:

- domains and labels
- shared observable and payload types
- algebra and scalar / point owners
- Fiat-Shamir surface
- budget parameters

### `ms/`

Carries the MS proof stack and its split subtrees.

- `SchnorrBranch.ec`, `BitnessOne.ec`, `BitnessVector.ec`, and `TranscriptObservable.ec` form the lower foundation.
- `true_clause/` and `comparison/` carry the split MS-3b and MS-3c leaf chains.
- `source/` carries the MS-3a source-model and execution/public-spine chain.
- `SourceModel.ec` and `MS.ec` provide the theorem-facing wrapper surfaces.

### `le/`

Carries the LE theorem stack and its lower semantic surfaces.

- `LERealExecution.ec` owns the concrete real-execution carrier and sampler.
- `LESurface.ec` owns the theorem-facing observable, views, and budget-facing operators.
- `LERejectionSampler.ec` and `LEFsProgrammingSurface.ec` host the lower rejection / FS surfaces.
- `LERejection.ec`, `LEFsProgramming.ec`, `LEStatisticalDistance.ec`, and `LEHVZK.ec` package those lower results into the live theorem path.
- `LEModel.ec` stays as the theorem-facing facade.

### `sim/`

`Simulator.ec` bridges the extracted MS public surface to the LE real-view surface.

### `games/`

Owns the explicit game constructors and additive arithmetic.

- `GameViews.ec` defines the concrete view constructors.
- `GameAdvantage.ec` owns `game_pr`, `Adv`, and transition arithmetic.
- `GameMSHops.ec` packages the MS hop chain.
- `GameLEBridge.ec` packages the LE bridge.
- `Games.ec` is the stable facade.

### `theorem/`

`MainTheorem.ec` is the top-level additive theorem layer.

## Stable Facades

These are the primary theorem-facing entrypoints for downstream proof users:

- `ms/TrueClause.ec`
- `ms/Comparison.ec`
- `ms/SourceModel.ec`
- `ms/MS.ec`
- `le/LEModel.ec`
- `games/Games.ec`
- `theorem/MainTheorem.ec`

## Directory Layout

```text
docs/03-formal-verification/easycrypt/
├── README.md
├── check_easycrypt.sh
├── formal/
├── primitives/
├── ms/
│   ├── TrueClause.ec
│   ├── Comparison.ec
│   ├── SourceModel.ec
│   ├── true_clause/
│   ├── comparison/
│   ├── source/
│   └── MS.ec
├── le/
├── sim/
├── games/
├── theorem/
└── plans/
```

Local subtree guides exist in:

- [../ms/source/README.md](../ms/source/README.md)
- [../ms/comparison/README.md](../ms/comparison/README.md)
- [../games/README.md](../games/README.md)

## Legacy File Map

| Former root file | Current location |
|------------------|-------------------|
| `QssmDomains.ec` | `primitives/Domains.ec` |
| `QssmTypes.ec` | `primitives/QssmTypes.ec` |
| `QssmFS.ec` | `primitives/FS.ec` |
| `QssmSchnorrSingleBit.ec` | `primitives/Algebra.ec` + `ms/SchnorrBranch.ec` |
| `QssmMSBitnessSingle.ec` | `ms/BitnessOne.ec` |
| `QssmMSBitnessVector.ec` | `ms/BitnessVector.ec` |
| `QssmMSTranscriptObservable.ec` | `ms/TranscriptObservable.ec` |
| `QssmMSTrueClause.ec` | `ms/TrueClause.ec` + `ms/true_clause/TrueClause{Types,MSB,Theorem}.ec` |
| `QssmMSComparison.ec` | `ms/Comparison.ec` + `ms/comparison/*.ec` |
| `QssmMS.ec` (bulk) | `ms/SourceModel.ec` + `ms/source/*.ec` |
| `QssmMS.ec` (facade) | `ms/MS.ec` |
| `QssmLE.ec` | `le/LEModel.ec` + `le/LESurface.ec` ... `le/LEHVZK.ec` |
| `QssmSim.ec` | `sim/Simulator.ec` |
| `QssmGames.ec` | `games/Games.ec` + `games/Game*.ec` |
| `QssmTheorem.ec` | `theorem/MainTheorem.ec` |

## Design Pattern

The recurring pattern across the tree is:

- keep theorem-facing names stable
- add richer lower semantic surfaces underneath those names
- prove bridge lemmas from the lower surfaces back to the theorem-facing marginals or views
- only route the theorem-facing endpoint through the richer surface after the lower lane is locally closed

That pattern is what allowed the LE rejection and FS theorem-facing endpoints to move onto semantic shadow lanes without forcing a simultaneous rewrite of `LEStatisticalDistance.ec` or `MainTheorem.ec`.

## Related Documents

- [PROOF_STATUS.md](PROOF_STATUS.md)
- [ASSUMPTIONS.md](ASSUMPTIONS.md)
- [PROOF_HISTORY.md](PROOF_HISTORY.md)
- [LE_REFINEMENT_PLAN.md](LE_REFINEMENT_PLAN.md)