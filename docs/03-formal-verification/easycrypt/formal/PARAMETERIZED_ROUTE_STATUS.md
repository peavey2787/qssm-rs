# Parameterized Route Status

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document records which parameterized lanes are complete, which ones are only staged, and which ones remain intentionally unstated at the frozen May 2026 checkpoint.

Current checker snapshot: `OK` over 149 checked theories; `axiom_count=0`; `admit_count=0`.

This document tracks only the concrete parameterized route. The parallel abstract real-world upper-bound surface lives in `RealWorldBudgetParameters.ec`, `RealWorldBudgetObligations.ec`, `LEStatisticalDistanceRealWorld.ec`, `MSProbabilitySurfaceRealWorld.ec`, `GameLEBridgeRealWorld.ec`, `GameMSHopCompositionRealWorld.ec`, and `MainTheoremRealWorld.ec`; the concrete external-bound instantiation surface now also lives in `RealWorldBudgetInstantiation.ec`; and the reduction-facing concrete companion layer lives in `LERejectionConcreteReduction.ec`, `LEFsConcreteReduction.ec`, `LEConcreteReduction.ec`, `MS1ConcreteReduction.ec`, `MS2ConcreteReduction.ec`, and `MSConcreteReduction.ec`. All of those parallel surfaces are axiom-free, all remain explicit about the duplicate MS2 charge and the public AfterRom caveat, and none changes the frozen `15%r / 64%r` concrete route summarized here or adds weighted/non-uniform sampler semantics.

## Route Status Table

| Lane | Owner-complete | Bridge-complete | Staged-only | Canonical-route-complete | Top-theorem-complete | Notes |
|---|---|---|---|---|---|---|
| MS1 parameterized owner | Yes | Yes, live owner surface | No | Yes, inside the MS route | No by itself | `ParameterizedBudgetParameters.ec` plus `SourceHashBindingSemanticSlotMassParameterized.ec` fix the active `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64` profile and both local MS1 masses |
| MS1 live parameterized bridge lane | Yes | Yes, live parameterized | No | Yes, via canonical failure and staged public-endpoint wrappers | No by itself | `SourceHashBindingSemanticLiveParameterizedCore.ec`, `SourceHashBindingSemanticLiveParameterizedMass.ec`, and `SourceHashBindingSemanticBridgeParameterized.ec` now carry canonical failure at `3%r / 64%r` and the staged public-divergence upper lane at `1%r / 32%r` |
| MS2 parameterized owner | Yes | Yes, live owner surface | No | Yes, through the live bridge lane | No by itself | `ParameterizedBudgetParameters.ec` plus `ComparisonPayloadSemanticSlotMassParameterized.ec` fix the active `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64` profile |
| MS2 live parameterized bridge lane | Yes | Yes, live parameterized | No | Yes, via staged public-endpoint and canonical landing wrappers | No by itself | `ComparisonPayloadSemanticLiveParameterizedCore.ec`, `ComparisonPayloadSemanticLiveParameterizedMass.ec`, and `ComparisonPayloadSemanticBridgeParameterized.ec` now carry the live MS2 execution-owned/public-AfterRom route at `3%r / 64%r` |
| Combined MS parameterized public-endpoint lane | Yes | Yes, live MS1 plus live MS2 | Yes, as an internal route | Consumed by canonical closure | No by itself | `MSProbabilitySurfaceParameterized.ec` through `GameMSHopCompositionParameterized.ec` now use live MS1 and live MS2 lower lanes while preserving the explicit duplicated MS2 charge |
| LE rejection parameterized lane | Yes | Yes, live parameterized sampler route | No | Yes, inside `G1 -> G2` | No by itself | `LERejectionSamplerParameterizedCore.ec` plus `LERejectionSamplerMassLiveParameterized.ec` own the live 3/64 rejection lane; `LERejectionParameterized.ec` and `LEStatisticalDistanceParameterized.ec` now route through `d_le_parameterized_post_rejection_view` rather than the demo rejection midpoint |
| LE FS parameterized lane | Yes | Yes, live parameterized branch/mass route | No | Yes, inside `G1 -> G2` | No by itself | `LEFsProgrammingLiveParameterizedCore.ec` plus `LEFsProgrammingLiveParameterizedMass.ec` own the live 3/64 FS lane, while `LEFsProgrammingParameterizedView.ec` and `LEFsProgrammingParameterized.ec` route the theorem-facing FS bridge through that midpoint and mass closure |
| LE parameterized umbrella | Yes | Yes | No | Yes, for `G1 -> G2` | Indirectly yes | `LEStatisticalDistanceParameterized.ec`, `LEHVZKParameterized.ec`, and `GameLEBridgeParameterized.ec` now compose over the parameterized rejection midpoint plus the FS-facing parameterized view bridge |
| LE-only parameterized top theorem | Yes | Yes | No | Yes, with canonical MS retained | Yes | `qssm_main_theorem_le_parameterized_budget` remains the LE-only intermediate theorem |
| Full canonical parameterized QSSM theorem | Yes | Yes, with live MS1, live MS2, and explicit extra MS2 charge | Not applicable | Yes | Yes | `qssm_main_theorem_parameterized_budget` closes through live MS1, live MS2, a budgeted public AfterRom to canonical AfterRom bridge, and an explicit duplicated MS2 term at active closed form `15%r / 64%r` |

## Structurally Durable Versus Temporary Layers

### Structurally durable

These files should remain part of the architecture even after production-count divergence is introduced.

- `primitives/ParameterizedBudgetParameters.ec`
- `ms/source/SourceHashBindingSemanticSlotMassParameterized.ec`
- `ms/source/SourceHashBindingSemanticLiveParameterizedCore.ec`
- `ms/source/SourceHashBindingSemanticLiveParameterizedMass.ec`
- `ms/source/SourceHashBindingSemanticBridgeParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticSlotMassParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticLiveParameterizedCore.ec`
- `ms/comparison/ComparisonPayloadSemanticLiveParameterizedMass.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `ms/MSProbabilitySurfaceParameterized.ec`
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

None are expected on the active uniform finite-support / contiguous-layout live family. The current theorem-facing MS1, MS2, and LE parameterized routes are now all carried by live lower lanes rather than active demo/parameterized alias bridges.

## What Is Complete Today

- Parameterized owner definitions are present for MS1, MS2, LE rejection, LE FS, and the parameterized LE umbrella.
- The LE parameterized lane now carries a live rejection route with counts `soft=1`, `hard=1`, `invalid=1`, `accept=61`, `failure=3`, `total=64`, so `epsilon_le_rej_parameterized = 3%r / 64%r`.
- The LE parameterized lane now also carries a live FS route with counts `query_collision=1`, `programming_collision=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_le_fs_parameterized = 3%r / 64%r`.
- `LERejectionParameterized.ec`, `LEFsProgrammingParameterized.ec`, `LEFsProgrammingParameterizedView.ec`, and `LEStatisticalDistanceParameterized.ec` now route through those live LE midpoints without changing the demo semantic theorem path.
- `epsilon_le_parameterized = 6%r / 64%r = 3%r / 32%r` now reaches the closed theorem surface.
- Those LE owner retunings changed no theorem-facing surface and required no local proof repair.
- The MS1 parameterized lane now carries a live canonical failure route with counts `collision=1`, `malformed_binding=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_ms_hash_binding_parameterized = 3%r / 64%r`.
- The MS1 staged public-divergence upper lane is now live parameterized at `malformed_binding + transcript = 2%r / 64%r = 1%r / 32%r`, and the staged/public-endpoint MS1 route is no longer demo-bound.
- The routed MS1 upper-mass theorem `ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized` in `SourceHashBindingSemanticSlotMassParameterized.ec` now closes through subset-helper infrastructure from `ParameterizedMassHelpers.ec` using `drange_subset_true_mass`, `drange_subset_true_mass_le_bound`, and `drange_subset_complement_mass`, with no theorem-facing rename and no change to the active `15%r / 64%r` route.
- `SourceHashBindingSemanticLiveParameterizedCore.ec` owns the live MS1 coupled-state/public-observable core, `SourceHashBindingSemanticLiveParameterizedMass.ec` owns live MS1 canonical failure and public-divergence upper mass closure, and `SourceHashBindingSemanticBridgeParameterized.ec`, `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` now carry that live staged route.
- The MS2 parameterized lane now also carries a live execution-owned route with counts `global_digest=1`, `query_digest=1`, `transcript=1`, `clean=61`, `failure=3`, `total=64`, so `epsilon_ms_rom_programmability_parameterized = 3%r / 64%r`.
- `ComparisonPayloadSemanticLiveParameterizedCore.ec` owns the live MS2 category/coupled-state/public-AfterRom core, `ComparisonPayloadSemanticLiveParameterizedMass.ec` owns the live MS2 execution-owned failure mass and public-divergence/failure closure, and `ComparisonPayloadSemanticBridgeParameterized.ec`, `MSProbabilitySurfaceParameterized.ec`, `GameAdvantageParameterized.ec`, `GameMSHopTypesParameterized.ec`, and `GameMSHopCompositionParameterized.ec` now carry the live staged/public-endpoint MS2 transition and budgeted landing route.
- All four component tuning pilots were owner-only changes after the live lower lanes were installed. They changed no theorem-facing surface and required no local proof repair.
- The LE parameterized lane closes all the way to `qssm_main_theorem_le_parameterized_budget`.
- The full canonical parameterized route closes all the way to `qssm_main_theorem_parameterized_budget`.
- Under the active live profiles, the full canonical parameterized top budget closes at `15%r / 64%r`.
- A parallel abstract real-world upper-bound theorem surface now also closes at head, but it leaves this parameterized status table unchanged and does not widen supported sampler geometry.
- A parallel concrete external-bound theorem family now also closes at head in `RealWorldBudgetInstantiation.ec`: the original theorem pair is still conditional on four explicit component-bound premises and does not internally discharge the current live `3%r / 64%r` lower actuals against `1 / 2^98`, while the newest sibling pair closes instead over four explicit reduction obligations exported by `LERejectionConcreteReduction.ec`, `LEFsConcreteReduction.ec`, `LEConcreteReduction.ec`, `MS1ConcreteReduction.ec`, `MS2ConcreteReduction.ec`, and `MSConcreteReduction.ec`.
- The staged/public-endpoint caveat is still explicit and part of the frozen proof claim because the canonical closure still factors through a charged public-endpoint landing.
- The exact-zero route and live demo semantic route remain unchanged.
- No remaining localized replay seams are expected on the current uniform finite-support / contiguous-layout profile family.

## What Is Intentionally Incomplete

- No zero-cost public-endpoint landing theorem from public AfterRom to canonical AfterRom.
- No theorem claiming public AfterRom is zero-equal to canonical AfterRom.
- No support for arbitrary non-uniform parameter profiles.
- No weighted/non-uniform sampler replay on the parallel real-world surface; that surface is abstract upper-bound only.

## Weighted Replay Boundary

The weighted replay audit does not change the concrete route status above.

- Weighted replay is only needed if the EasyCrypt tree must model weighted sampler internals directly.
- The preferred future owner shape is normalized per-component category weights.
- Per-slot weights are not the right first move.
- Component-failure-only records are too abstract because they mostly duplicate the current real-world obligation bundle.
- The first safe weighted pilot, if work ever resumes here, is an LE rejection weighted category owner only.

## Minimum Future Work For Profile Generalization

The next research phase, if reopened, starts below the theorem surface, but it is no longer a localized seam replay campaign.

1. Keep `BudgetParameters.ec`, `MainTheorem.ec`, demo MS files, and the exact-zero/demo semantic routes unchanged.
2. Generalize the current uniform finite-support / contiguous-layout parameter geometry if broader profile families are desired.
3. Re-validate the public-endpoint landing and canonical composition theorems above any generalized lower owner without hiding the duplicated MS2 charge.
4. Re-evaluate the remaining MS semantic distinction only if a zero-cost or tighter landing is required later.

The next recommended audit is therefore a profile-generalization audit rather than another localized replay audit.

## Research Backlog

These items are backlog only. They are not active proof obligations at the frozen release checkpoint.

- public AfterRom to canonical AfterRom semantic reconciliation
- profile generalization beyond the current uniform finite-support / contiguous-layout family
- tighter public AfterRom to canonical AfterRom bridge
- possible removal of the duplicated MS2 landing charge
- semantic/public observable reconciliation strategy
- stronger non-demo parameter semantics