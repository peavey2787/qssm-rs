# Formal Theorem Map

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document is the canonical external explanation of what the current EasyCrypt tree proves, how the theorem routes compose, which parameterized lanes are complete, which are intentionally incomplete, and why the current stopping point is mathematically honest.

The proof surface is frozen at the May 2026 release checkpoint.

- Current checker snapshot is `OK` over 133 checked theories, with `axiom_count=0` and `admit_count=0`.
- The exact-zero route remains unchanged.
- The live demo semantic route remains unchanged and still closes at `3%r / 4%r`.
- `qssm_main_theorem_le_parameterized_budget` exists and is closed as the LE-only intermediate theorem.
- `qssm_main_theorem_parameterized_budget` exists and is closed as the full canonical parameterized theorem.
- The full parameterized top budget is `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized`.
- The lower MS public-endpoint distinction remains real: public AfterRom is budget-close to canonical AfterRom, not zero-equal, so the route closes through a charged bridge.

## Public Theorem Surface

| Theorem | File | Status | Meaning |
|---|---|---|---|
| `qssm_main_theorem` | `theorem/MainTheorem.ec` | Closed | Exact-zero abstraction theorem on the live canonical route |
| `qssm_main_theorem_semantic_budget` | `theorem/MainTheorem.ec` | Closed | Live demo semantic theorem with top budget `3%r / 4%r` |
| `qssm_main_theorem_semantic_budget_umbrella` | `theorem/MainTheorem.ec` | Closed | Alias of the live demo semantic theorem |
| `qssm_main_theorem_nonzero_budget` | `theorem/MainTheorem.ec` | Closed | Discoverability alias of the live demo semantic theorem |
| `qssm_main_theorem_le_parameterized_budget` | `theorem/MainTheoremParameterized.ec` | Closed | LE-only parameterized theorem that keeps the MS contribution on the canonical/demo semantic route |
| `qssm_main_theorem_parameterized_budget` | `theorem/MainTheoremParameterized.ec` | Closed | Full canonical parameterized theorem with explicit budget `epsilon_ms_hash_binding_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_ms_rom_programmability_parameterized + epsilon_le_parameterized` |

## Route Split

The current theorem system has five distinct routes.

| Route | Top surface | Current status | Notes |
|---|---|---|---|
| Exact-zero route | `qssm_main_theorem` | Live | Canonical public theorem route |
| Demo semantic route | `qssm_main_theorem_semantic_budget` | Live | Canonical demo semantic route with top `3%r / 4%r` |
| LE-only parameterized route | `qssm_main_theorem_le_parameterized_budget` | Live | Keeps canonical/demo MS contribution and parameterizes only LE |
| Full canonical parameterized route | `qssm_main_theorem_parameterized_budget` | Live | Closes through a budgeted public AfterRom to canonical AfterRom bridge with an explicit duplicated MS2 term |
| Staged/public-endpoint MS parameterized route | No separate top theorem | Live as an internal route | Remains the internal public-endpoint subroute consumed by the canonical parameterized closure |

## Exact-Zero Route

The exact-zero route is the public baseline.

| Layer | File | Main symbols |
|---|---|---|
| Primitive owners | `primitives/BudgetParameters.ec` | `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, `epsilon_le` |
| Canonical MS composition | `games/GameMSHopComposition.ec` | `A_G0_to_G1_ms_transition_bound` |
| Canonical LE bridge | `games/GameLEBridge.ec` | `A_G1_to_G2_le_transition_bound` |
| Top additive wrapper | `theorem/MainTheorem.ec` | `qssm_main_theorem_skeleton`, `qssm_main_theorem` |

Operationally, `qssm_main_theorem` is just the exact-zero corollary of `qssm_main_theorem_skeleton` once the current budget definitions rewrite to `0%r`.

## Demo Semantic Route

The live demo semantic route is the only non-exact route claimed on the canonical theorem surface.

### MS1 semantic segment

| Layer | File | Main symbols |
|---|---|---|
| Primitive owner | `primitives/BudgetParameters.ec` | `epsilon_ms_hash_binding_semantic` |
| Local owner closure | `ms/source/SourceHashBindingSemanticSlotMass.ec` | local slot/mass closure for the semantic MS1 owner |
| Execution-owned bridge | `ms/source/SourceHashBindingSemanticBridge.ec` | `A_MS1_hash_binding_execution_owned_semantic_bound` |
| Probability surface | `ms/MSProbabilitySurface.ec` | `A_MS1_hash_binding_semantic_bad_event_bound`, `A_MS1_hash_binding_semantic_transition_bound` |
| Game routing | `games/GameMSHopTransitions.ec`, `games/GameMSHopComposition.ec` | `A_MS1_hash_binding_semantic_transition`, `A_G0_to_G1_ms_hash_binding_semantic_transition_bound` |

### MS2 semantic segment

| Layer | File | Main symbols |
|---|---|---|
| Primitive owner | `primitives/BudgetParameters.ec` | `epsilon_ms_rom_programmability_semantic` |
| Local owner closure | `ms/comparison/ComparisonPayloadSemanticSlotMass.ec` | local slot/mass closure for the semantic MS2 owner |
| Execution-owned bridge | `ms/comparison/ComparisonPayloadSemanticBridge.ec` | `A_MS2_rom_programming_execution_owned_semantic_bound` |
| Probability surface | `ms/MSProbabilitySurface.ec` | `A_MS2_rom_programming_semantic_transition_bound`, `A_MS2_rom_programming_semantic_public_endpoint_transition_bound` |
| Game routing | `games/GameMSHopTransitions.ec`, `games/GameMSHopComposition.ec` | `A_MS2_rom_programming_semantic_transition`, `A_G0_to_G1_ms_semantic_transition_bound` |

### LE semantic segment

| Layer | File | Main symbols |
|---|---|---|
| Rejection owner | `primitives/BudgetParameters.ec` | `epsilon_le_rej_semantic` |
| Rejection lower closure | `le/LERejectionSamplerMass.ec`, `le/LERejection.ec` | `A_LE_rejection_sampler_semantic_sdist_bound` |
| FS owner | `primitives/BudgetParameters.ec` | `epsilon_le_fs_semantic` |
| FS lower closure | `le/LEFsProgrammingFailureProbability.ec`, `le/LEFsProgramming.ec` | `le_fs_shadow_local_bad_branch_mass`, `A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass` |
| LE bridge | `games/GameLEBridge.ec` | `A_G1_to_G2_le_semantic_transition_bound`, `A_G1_to_G2_le_semantic_owned_budget_transition_bound`, `A_G1_to_G2_le_semantic_umbrella_transition_bound` |

### Top semantic wrapper

| Layer | File | Main symbols |
|---|---|---|
| Top local-mass wrapper | `theorem/MainTheorem.ec` | `qssm_main_theorem_semantic_budget_local_mass` |
| Top owned-budget wrapper | `theorem/MainTheorem.ec` | `qssm_main_theorem_semantic_budget_owned` |
| Top umbrella wrapper | `theorem/MainTheorem.ec` | `qssm_main_theorem_semantic_budget`, `qssm_main_theorem_semantic_budget_umbrella`, `qssm_main_theorem_nonzero_budget` |

The live demo semantic theorem therefore closes as:

```text
MS.epsilon_ms_hash_binding_semantic
+ epsilon_ms_rom_programmability_semantic
+ BudgetParameters.epsilon_le_semantic
= 3%r / 4%r
```

## LE-Only Parameterized Route

The LE-only parameterized route is complete and intentionally narrow.

| Layer | File | Main symbols |
|---|---|---|
| Parameterized owners | `primitives/ParameterizedBudgetParameters.ec` | `epsilon_le_rej_parameterized`, `epsilon_le_fs_parameterized`, `epsilon_le_parameterized` |
| Rejection parameterized lane | `le/LERejectionSamplerParameterizedCore.ec`, `le/LERejectionSamplerMassLiveParameterized.ec`, `le/LERejectionParameterized.ec` | live parameterized rejection core, mass/sdist closure, and theorem-facing bridge at `epsilon_le_rej_parameterized = 3%r / 32%r` |
| FS parameterized lane | `le/LEFsProgrammingFailureProbabilityParameterized.ec`, `le/LEFsProgrammingLiveParameterizedCore.ec`, `le/LEFsProgrammingLiveParameterizedMass.ec`, `le/LEFsProgrammingParameterizedView.ec`, `le/LEFsProgrammingParameterized.ec` | live parameterized FS owner/midpoint/mass closure and theorem-facing bridge at `epsilon_le_fs_parameterized = 3%r / 32%r` |
| LE parameterized additive bridge | `le/LEStatisticalDistanceParameterized.ec`, `le/LEHVZKParameterized.ec` | parameterized LE advantage closure |
| Game bridge | `games/GameLEBridgeParameterized.ec` | `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound` |
| Top theorem | `theorem/MainTheoremParameterized.ec` | `qssm_main_theorem_le_parameterized_budget` |

This route keeps the MS contribution on `A_G0_to_G1_ms_semantic_transition_bound` and swaps only the LE side.

Both LE rejection and LE FS have moved below the demo `3%r / 16%r` profile on the active parameterized lane. The demo route remains unchanged, `epsilon_le_rej_parameterized = 3%r / 32%r`, `epsilon_le_fs_parameterized = 3%r / 32%r`, and therefore `epsilon_le_parameterized = 3%r / 16%r`.

## Full Canonical Parameterized Route

The full canonical parameterized route is now complete and honest about the extra MS2 landing cost.

| Layer | File | Main symbols |
|---|---|---|
| Parameterized owners | `primitives/ParameterizedBudgetParameters.ec` | `epsilon_ms_hash_binding_parameterized`, `epsilon_ms_rom_programmability_parameterized`, `epsilon_le_parameterized` |
| Live MS1 coupled-state/public core | `ms/source/SourceHashBindingSemanticLiveParameterizedCore.ec` | `d_ms_hash_binding_semantic_coupled_state_parameterized`, `d_ms_hash_binding_public_semantic_observable_v2_parameterized`, `d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized` |
| Live MS1 mass closure | `ms/source/SourceHashBindingSemanticLiveParameterizedMass.ec` | `A_MS1_hash_binding_execution_owned_live_parameterized_bound`, `ms_hash_binding_public_divergence_upper_pair_choice_mass_eq_local_upper_mass_live_parameterized`, `ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_live_parameterized` |
| Parameterized MS1 bridge + surface | `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`, `ms/MSProbabilitySurfaceParameterized.ec` | preserved canonical/staged theorem names delegated to the live MS1 lane at `epsilon_ms_hash_binding_parameterized = 3%r / 32%r` and staged upper mass `1%r / 16%r` |
| Budgeted public-to-canonical bridge | `ms/MSProbabilitySurfaceParameterized.ec` | `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound` |
| Game-layer landing | `games/GameAdvantageParameterized.ec`, `games/GameMSHopTypesParameterized.ec`, `games/GameMSHopCompositionParameterized.ec` | live MS1 staged/public-endpoint route plus canonical landing with explicit duplicated MS2 charge |
| Parameterized LE bridge | `games/GameLEBridgeParameterized.ec` | `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound` |
| Top theorem | `theorem/MainTheoremParameterized.ec` | `qssm_main_theorem_parameterized_budget` |

The active live MS1 profile on this route is `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=29`, `failure=3`, `total=32`, so the canonical failure lane closes at `3%r / 32%r` and the staged public-divergence upper lane closes at `2%r / 32%r = 1%r / 16%r`.

The closed top-level budget is:

```text
epsilon_ms_hash_binding_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_le_parameterized
```

## Staged/Public-Endpoint MS Parameterized Route

The MS parameterized lane still factors through a staged public-endpoint route, but that route is now an internal component of the closed canonical parameterized theorem.

| Layer | File | Main symbols |
|---|---|---|
| Parameterized owners | `primitives/ParameterizedBudgetParameters.ec` | `epsilon_ms_hash_binding_parameterized`, `epsilon_ms_rom_programmability_parameterized` |
| Live MS1 public-endpoint core | `ms/source/SourceHashBindingSemanticLiveParameterizedCore.ec` | `d_ms_hash_binding_public_semantic_observable_v2_parameterized`, `d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized` |
| Live MS1 staged mass closure | `ms/source/SourceHashBindingSemanticLiveParameterizedMass.ec` | live staged/public-divergence upper closure at `1%r / 16%r` |
| Parameterized bridge companions | `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`, `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec` | live MS1 bridge delegation plus the remaining MS2 companion theorems |
| Parameterized probability surface | `ms/MSProbabilitySurfaceParameterized.ec` | `A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound`, `A_MS_public_endpoint_parameterized_transition_bound`, and the budgeted public AfterRom to canonical AfterRom landing theorem |
| Parameterized game wrappers | `games/GameAdvantageParameterized.ec`, `games/GameMSHopTypesParameterized.ec`, `games/GameMSHopCompositionParameterized.ec` | live staged/public-endpoint MS1 wrappers plus the canonical parameterized composition theorem |

This lane still carries `A_MS_public_endpoint_parameterized_staged_composition_bound`, but it no longer stops there. The MS1 half of the public-endpoint subroute is no longer demo-bound, and the staged/public-endpoint route is now consumed by the budgeted landing theorem and the canonical composition theorem `A_G0_to_G1_ms_parameterized_transition_bound`.

## What Is Intentionally Not Proved

- There is no zero-cost canonicalization theorem from public AfterRom to canonical AfterRom.
- There is no theorem claim that the staged/public-endpoint MS route has re-entered the canonical `Adv_G0_G1_MS` telescope.
- There is no theorem claiming `public AfterRom = canonical AfterRom` or `sdist(public AfterRom, canonical AfterRom) = 0`.

## Why The Current Stopping Point Is Honest

The frozen theorem surface matches the proofs that actually close.

- The exact-zero route is claimed only where exact-zero closure exists.
- The demo semantic route is claimed only where the current demo semantic owners have been routed through the canonical theorem stack.
- The LE-only parameterized theorem remains claimed because the LE parameterized lane closes and the MS contribution can still be left on the already-closed canonical/demo semantic route.
- The full canonical parameterized theorem is now claimed only because the semantic public-to-canonical MS gap was closed honestly by paying an explicit extra `epsilon_ms_rom_programmability_parameterized` term rather than by asserting a zero bridge.

That semantic distinction and its charged closure are analyzed in [SEMANTIC_GAP_ANALYSIS.md](SEMANTIC_GAP_ANALYSIS.md).