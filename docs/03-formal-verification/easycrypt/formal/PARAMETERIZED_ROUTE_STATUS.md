# Parameterized Route Status

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document records which parameterized lanes are complete, which ones are only staged, and which ones remain intentionally unstated at the frozen May 2026 checkpoint.

## Route Status Table

| Lane | Owner-complete | Bridge-complete | Staged-only | Canonical-route-complete | Top-theorem-complete | Notes |
|---|---|---|---|---|---|---|
| MS1 parameterized owner | Yes | Local owner only | No | No | No | `ParameterizedBudgetParameters.ec` plus `SourceHashBindingSemanticSlotMassParameterized.ec` are real parameterized owner surfaces |
| MS1 parameterized bridge companion | Yes | Yes, alias-based | Yes | No | No | `SourceHashBindingSemanticBridgeParameterized.ec` still relies on equality between semantic and parameterized demo counts |
| MS2 parameterized owner | Yes | Local owner only | No | No | No | `ParameterizedBudgetParameters.ec` plus `ComparisonPayloadSemanticSlotMassParameterized.ec` are real parameterized owner surfaces |
| MS2 parameterized bridge companion | Yes | Yes, alias-based | Yes | No | No | `ComparisonPayloadSemanticBridgeParameterized.ec` still relies on equality between semantic and parameterized demo counts |
| Combined MS parameterized public-endpoint lane | Yes | Yes, alias-based | Yes | No | No | `MSProbabilitySurfaceParameterized.ec` through `GameMSHopCompositionParameterized.ec` closes only as a staged/public-endpoint lane |
| LE rejection parameterized lane | Yes | Yes, partly alias-based | No | Yes, inside `G1 -> G2` | No by itself | Lower owner surface is real; theorem-facing companion still uses alias equality to the demo semantic owner |
| LE FS parameterized lane | Yes | Yes, partly alias-based | No | Yes, inside `G1 -> G2` | No by itself | Lower owner surface is real; theorem-facing companion still uses alias equality to the demo semantic owner |
| LE parameterized umbrella | Yes | Yes | No | Yes, for `G1 -> G2` | Indirectly yes | `LEStatisticalDistanceParameterized.ec`, `LEHVZKParameterized.ec`, and `GameLEBridgeParameterized.ec` close the LE parameterized route |
| LE-only parameterized top theorem | Yes | Yes | No | Yes, with canonical MS retained | Yes | `qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate theorem |
| Full canonical parameterized QSSM theorem | Yes | Yes, with explicit extra MS2 charge | Not applicable | Yes | Yes | `qssm_main_theorem_parameterized_budget` closes through a budgeted public AfterRom to canonical AfterRom bridge and keeps the duplicated MS2 term explicit |

## Structurally Durable Versus Temporary Layers

### Structurally durable

These files should remain part of the architecture even after production-count divergence is introduced.

- `primitives/ParameterizedBudgetParameters.ec`
- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
- `le/LERejectionSamplerMassParameterized.ec`
- `le/LEFsProgrammingFailureProbabilityParameterized.ec`
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
- `le/LERejectionParameterized.ec`
- `le/LEFsProgrammingParameterized.ec`

## What Is Complete Today

- Parameterized owner definitions are present for MS1, MS2, LE rejection, LE FS, and the parameterized LE umbrella.
- The LE parameterized lane closes all the way to `qssm_main_theorem_le_parameterized_budget`.
- The full canonical parameterized route closes all the way to `qssm_main_theorem_parameterized_budget`.
- The staged/public-endpoint caveat is still explicit and part of the frozen proof claim because the canonical closure still factors through a charged public-endpoint landing.

## What Is Intentionally Incomplete

- No zero-cost public-endpoint landing theorem from public AfterRom to canonical AfterRom.
- No theorem claiming public AfterRom is zero-equal to canonical AfterRom.
- No production-count substitution for the current demo-alias bridge companions.

## Minimum Future Work For True Production-Count Substitution

The next research phase, if reopened, starts below the theorem surface.

1. Introduce a genuinely non-demo parameter owner surface without mutating `BudgetParameters.ec`.
2. Replace alias-based MS1 and MS2 bridge companions with real execution-owned parameterized bridge proofs.
3. Replace alias-based LE rejection and LE FS theorem-facing companions with real semantic-to-parameterized bridge proofs.
4. Tighten or replace the current alias-based public-to-canonical landing if a future route wants to remove the duplicated MS2 charge honestly.
5. Re-evaluate the remaining MS semantic distinction only if a zero-cost or tighter landing is required later.

## Research Backlog

These items are backlog only. They are not active proof obligations at the frozen release checkpoint.

- public AfterRom to canonical AfterRom semantic reconciliation
- true production-count substitution
- removal of alias-based parameterized bridge equalities
- tighter public AfterRom to canonical AfterRom bridge
- possible removal of the duplicated MS2 landing charge
- semantic/public observable reconciliation strategy
- stronger non-demo parameter semantics