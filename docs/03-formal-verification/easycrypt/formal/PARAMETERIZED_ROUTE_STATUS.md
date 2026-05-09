# Parameterized Route Status

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document records which parameterized lanes are complete, which ones are only staged, and which ones remain intentionally unstated at the frozen May 2026 checkpoint.

Current checker snapshot: `OK` over 131 checked theories; `axiom_count=0`; `admit_count=0`.

## Route Status Table

| Lane | Owner-complete | Bridge-complete | Staged-only | Canonical-route-complete | Top-theorem-complete | Notes |
|---|---|---|---|---|---|---|
| MS1 parameterized owner | Yes | Local owner only | No | No | No | `ParameterizedBudgetParameters.ec` plus `SourceHashBindingSemanticSlotMassParameterized.ec` are real parameterized owner surfaces |
| MS1 parameterized bridge companion | Yes | Yes, alias-based | Yes | No | No | `SourceHashBindingSemanticBridgeParameterized.ec` still relies on equality between semantic and parameterized demo counts |
| MS2 parameterized owner | Yes | Local owner only | No | No | No | `ParameterizedBudgetParameters.ec` plus `ComparisonPayloadSemanticSlotMassParameterized.ec` are real parameterized owner surfaces |
| MS2 parameterized bridge companion | Yes | Yes, alias-based | Yes | No | No | `ComparisonPayloadSemanticBridgeParameterized.ec` still relies on equality between semantic and parameterized demo counts |
| Combined MS parameterized public-endpoint lane | Yes | Yes, alias-based | Yes | No | No | `MSProbabilitySurfaceParameterized.ec` through `GameMSHopCompositionParameterized.ec` closes only as a staged/public-endpoint lane |
| LE rejection parameterized lane | Yes | Yes, live parameterized sampler route | No | Yes, inside `G1 -> G2` | No by itself | `LERejectionSamplerParameterizedCore.ec` plus `LERejectionSamplerMassLiveParameterized.ec` own the live 3/32 rejection lane; `LERejectionParameterized.ec` and `LEStatisticalDistanceParameterized.ec` now route through `d_le_parameterized_post_rejection_view` rather than the demo rejection midpoint |
| LE FS parameterized lane | Yes | Yes, live parameterized branch/mass route | No | Yes, inside `G1 -> G2` | No by itself | `LEFsProgrammingLiveParameterizedCore.ec` plus `LEFsProgrammingLiveParameterizedMass.ec` own the live 3/32 FS lane, while `LEFsProgrammingParameterizedView.ec` and `LEFsProgrammingParameterized.ec` route the theorem-facing FS bridge through that midpoint and mass closure |
| LE parameterized umbrella | Yes | Yes | No | Yes, for `G1 -> G2` | Indirectly yes | `LEStatisticalDistanceParameterized.ec`, `LEHVZKParameterized.ec`, and `GameLEBridgeParameterized.ec` now compose over the parameterized rejection midpoint plus the FS-facing parameterized view bridge |
| LE-only parameterized top theorem | Yes | Yes | No | Yes, with canonical MS retained | Yes | `qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate theorem |
| Full canonical parameterized QSSM theorem | Yes | Yes, with explicit extra MS2 charge | Not applicable | Yes | Yes | `qssm_main_theorem_parameterized_budget` closes through a budgeted public AfterRom to canonical AfterRom bridge and keeps the duplicated MS2 term explicit |

## Structurally Durable Versus Temporary Layers

### Structurally durable

These files should remain part of the architecture even after production-count divergence is introduced.

- `primitives/ParameterizedBudgetParameters.ec`
- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
- `le/LERejectionSamplerParameterizedCore.ec`
- `le/LERejectionSamplerMassLiveParameterized.ec`
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`
- `le/LEFsProgrammingLiveParameterizedCore.ec`
- `le/LEFsProgrammingLiveParameterizedMass.ec`
- `le/LEFsProgrammingParameterizedView.ec`
- `le/LEFsProgrammingParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopTypesParameterized.ec`
- `games/GameMSHopCompositionParameterized.ec`
- `le/LEStatisticalDistanceParameterized.ec`
- `le/LEHVZKParameterized.ec`
- `games/GameLEBridgeParameterized.ec`
- `theorem/MainTheoremParameterized.ec`

### Demo-alias temporary wrappers

These files are architecturally useful today, but their current proofs still depend on alias equalities between the demo semantic owners and the parameterized owners.

- `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `ms/MSProbabilitySurfaceParameterized.ec`

## What Is Complete Today

- Parameterized owner definitions are present for MS1, MS2, LE rejection, LE FS, and the parameterized LE umbrella.
- The LE parameterized lane now carries a live rejection route with counts `soft=1`, `hard=1`, `invalid=1`, `accept=29`, `failure=3`, `total=32`, so `epsilon_le_rej_parameterized = 3%r / 32%r`.
- The LE parameterized lane now also carries a live FS route with counts `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so `epsilon_le_fs_parameterized = 3%r / 32%r`.
- `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, `LEFsProgrammingParameterizedView.ec`, and `LEStatisticalDistanceParameterized.ec` now route through those live LE midpoints without changing the demo semantic theorem path.
- `epsilon_le_parameterized = 6%r / 32%r = 3%r / 16%r` now reaches the closed theorem surface.
- The LE parameterized lane closes all the way to `qssm_main_theorem_le_parameterized_budget`.
- The full canonical parameterized route closes all the way to `qssm_main_theorem_parameterized_budget`.
- The staged/public-endpoint caveat is still explicit and part of the frozen proof claim because the canonical closure still factors through a charged public-endpoint landing.
- The exact-zero route and live demo semantic route remain unchanged.

## What Is Intentionally Incomplete

- No zero-cost public-endpoint landing theorem from public AfterRom to canonical AfterRom.
- No theorem claiming public AfterRom is zero-equal to canonical AfterRom.
- No production-count substitution for the remaining demo-alias MS bridge companions.
- No honest lowering of the MS1 or MS2 parameterized budgets beyond their current demo-derived bridge surfaces.

## Minimum Future Work For True Production-Count Substitution

The next research phase, if reopened, starts below the theorem surface.

1. Introduce genuinely non-demo parameter owner surfaces for MS1 and MS2 without mutating `BudgetParameters.ec`.
2. Replace the alias-based MS1 local-failure bridge companion with a real execution-owned parameterized bridge proof.
3. Replay the MS1 public-divergence upper comparison under genuinely independent parameterized counts.
4. Replace the alias-based MS2 local-failure bridge companion with a real execution-owned parameterized bridge proof.
5. Re-evaluate the remaining MS semantic distinction only if a zero-cost or tighter landing is required later.

The next recommended audit is the MS1 local-failure and public-divergence replay pair.

## Research Backlog

These items are backlog only. They are not active proof obligations at the frozen release checkpoint.

- public AfterRom to canonical AfterRom semantic reconciliation
- true production-count substitution
- removal of alias-based parameterized bridge equalities
- tighter public AfterRom to canonical AfterRom bridge
- possible removal of the duplicated MS2 landing charge
- semantic/public observable reconciliation strategy
- stronger non-demo parameter semantics