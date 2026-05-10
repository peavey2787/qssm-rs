# Semantic Gap Analysis

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document explains the public AfterRom versus canonical AfterRom semantic distinction and how the full canonical parameterized theorem now closes honestly in its presence.

## The Gap

The public-to-canonical MS issue is not organizational. It is semantic.

The current lower MS surface distinguishes two different AfterRom endpoints.

- Canonical AfterRom observable: `d_ms_after_rom_observable_v2`
- Public semantic AfterRom observable: `d_ms_after_rom_public_semantic_observable_v2`

The canonical game route uses the canonical stage selector `d_ms_game_stage_observable_v2` and its AfterRom branch. The staged parameterized route uses the public-endpoint surface instead.

## What Is Proved Today

The following facts are available on the current lower surface.

- The canonical AfterRom observable collapses back to the canonical AfterBinding observable.
- The public semantic AfterRom observable is only bounded against the canonical surface by a charged semantic-failure term.
- The public-endpoint route can therefore be proved as a staged/public-endpoint route.
- On the MS1 half, that staged/public-endpoint route is now live parameterized at `2%r / 64%r = 1%r / 32%r` rather than demo-bound.
- On the MS2 half, both the staged public-endpoint transition and the public-to-canonical landing are now routed through a live execution-owned parameterized lane at `epsilon_ms_rom_programmability_parameterized = 3%r / 64%r`.
- The parameterized route can now land back in the canonical game chain by paying an explicit budgeted bridge charge.
- The abstract real-world upper-bound route now mirrors that same charged landing shape through `A_MS_public_after_rom_to_canonical_after_rom_realworld_transition_bound`, `A_G0_to_G1_ms_realworld_transition_bound`, and `qssm_main_theorem_realworld_budget`.
- The concrete reduction-facing sibling route now mirrors that same charged landing shape through `A_G0_to_G1_ms_concrete_reduction_transition_bound_from_obligations` and `qssm_main_theorem_realworld_concrete_128_with_all_reductions`.

In practical theorem names, the strongest relevant current facts are:

- `d_ms_after_rom_observable_v2_eq_after_binding`
- `d_ms_after_rom_observable_v2_canonical`
- `L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure`
- `A_MS2_rom_programming_semantic_public_endpoint_transition_bound`
- `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound`
- `A_G0_to_G1_ms_parameterized_transition_bound`
- `qssm_main_theorem_parameterized_budget`
- `A_G0_to_G1_ms_concrete_reduction_transition_bound_from_obligations`
- `qssm_main_theorem_realworld_concrete_128_with_all_reductions`

## What Is Not Proved

The following statements do not currently exist.

- Equality between public AfterRom and canonical AfterRom
- Zero statistical distance between public AfterRom and canonical AfterRom
- A zero-cost game-probability replacement from the staged/public-endpoint carrier into the canonical `Adv_G0_G1_MS` carrier

In particular, the tree does not currently prove any zero-cost theorem of the form:

```text
public AfterRom = canonical AfterRom
```

or:

```text
sdist(public AfterRom, canonical AfterRom) = 0
```

## Why This No Longer Blocks The Canonical Parameterized Route

The parameterized MS route still factors through the staged/public-endpoint chain:

```text
MSProbabilitySurfaceParameterized.ec
  -> GameAdvantageParameterized.ec
  -> GameMSHopTypesParameterized.ec
  -> GameMSHopCompositionParameterized.ec
```

That chain now re-enters the canonical `Adv_G0_G1_MS` telescope through a budgeted landing theorem rather than a zero-cost identification. The resulting canonical MS theorem and top theorem are:

- `A_G0_to_G1_ms_parameterized_transition_bound`
- `qssm_main_theorem_parameterized_budget`

The honest price of that landing is an explicit duplicated MS2 term, so the closed top budget is:

```text
epsilon_ms_hash_binding_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_le_parameterized
```

Under the active live profiles, that charged top budget evaluates to `15%r / 64%r`.

## What The Abstract Real-World Surface Adds

`RealWorldBudgetParameters.ec`, `RealWorldBudgetObligations.ec`, `LEStatisticalDistanceRealWorld.ec`, `MSProbabilitySurfaceRealWorld.ec`, `GameLEBridgeRealWorld.ec`, `GameMSHopCompositionRealWorld.ec`, and `MainTheoremRealWorld.ec` now package the same charged landing story under explicit `le_realworld_obligations`, `ms_realworld_obligations`, and `qssm_realworld_obligations` hypotheses over externally supplied upper-bound budgets.

This surface is axiom-free because those obligations are theorem premises, not imported assumptions. It does not model weighted or non-uniform samplers, does not remove the public AfterRom caveat, and keeps the duplicate MS2 charge explicit in the theorem-facing statement.

That abstract route is already sufficient when real-world budgets are supported by external evidence outside the EasyCrypt sampler internals. Weighted replay would only be needed if the tree must model those weighted sampler internals directly, and even then it should discharge the same obligations rather than replace `qssm_main_theorem_realworld_budget`.

`RealWorldBudgetInstantiation.ec` now adds a concrete external-bound instantiation surface on top of that abstract route. It packages `realworld_budget_concrete_128` with concrete component epsilon `1 / 2^98`, proves the top closed form `5 / 2^98`, keeps the original theorem pair `qssm_main_theorem_realworld_concrete_128` and `qssm_main_theorem_realworld_concrete_128_5_over_2_98` under four explicit component-bound premises, and now also closes the fully reduction-facing sibling pair `qssm_main_theorem_realworld_concrete_128_with_all_reductions` and `qssm_main_theorem_realworld_concrete_128_with_all_reductions_5_over_2_98` under four explicit reduction obligations. This still does not internally prove those reductions, does not claim the current live `3%r / 64%r` lower actuals satisfy `1 / 2^98`, and does not remove the public AfterRom caveat.

## Why The Blocker Is Semantic, Not Organizational

The missing piece is not a forgotten wrapper in the game layer.

- The owner surfaces already exist.
- The staged public-endpoint wrappers already exist.
- The LE parameterized route already closes to the top theorem surface.
- The MS parameterized route already closes as far as the public-endpoint composition layer.

What remains missing is a stronger lower theorem about the actual relationship between the public AfterRom carrier and the canonical AfterRom carrier that would remove or reduce the charged landing term.

## If Research Reopens Here

The first honest owner boundary is still below the theorem surface if future work wants to tighten the new route.

On the current tree, the live LE rejection and live LE FS `3%r / 64%r` lanes are already closed, the MS1 canonical failure plus staged/public-endpoint lanes are live parameterized at `3%r / 64%r` and `1%r / 32%r`, the MS2 staged/public-endpoint plus landing route is live parameterized at `3%r / 64%r`, the parallel abstract real-world upper-bound theorem surface is checker-green, and the concrete external-bound theorem family is checker-green at `1 / 2^98` component epsilon and `5 / 2^98` top epsilon, including the fully reduction-facing sibling path over four explicit reduction obligations. The weighted replay audit is complete: weighted replay remains future work only for in-tree sampler modeling, the preferred future owner shape is normalized per-component category weights, per-slot weights are not the right first move, component-failure-only records mostly duplicate the current obligations, and the first safe pilot is an LE rejection weighted category owner only. No remaining localized replay seams are expected on the current uniform finite-support / contiguous-layout profile family, so the next focused step is either factoring shared concrete composition without hiding the duplicate MS2 charge, broader profile generalization, a stronger lower fusion law, or stop rather than another localized replay pass.

- Start at `ms/MSProbabilitySurface.ec` or a sibling lower companion.
- Do not start in `MainTheorem.ec`.
- Do not start by mutating theorem names.
- Do not start with a readability refactor.
- Do not treat the current gap as a packaging problem.

## Research Backlog

These items remain future research only.

- tighter public AfterRom to canonical AfterRom semantic reconciliation
- profile generalization beyond the current uniform finite-support / contiguous-layout family
- weighted sampler-internal replay below the existing real-world obligation surface
- potential removal of the duplicated MS2 landing charge
- semantic/public observable reconciliation strategy
- stronger non-demo parameter semantics

## Honest Conclusion

The current stopping point is mathematically honest because the theorem surface claims only the routes that actually close.

- exact-zero route: claimed and closed
- demo semantic route: claimed and closed
- LE-only parameterized route: claimed and closed
- canonical MS parameterized route: claimed and closed through a budgeted bridge with an explicit extra MS2 charge

The semantic distinction is unchanged: public AfterRom is budget-close to canonical AfterRom, not zero-equal. What changed is that the theorem surface now closes honestly by paying for that distinction.