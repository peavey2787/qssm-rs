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
- On the MS1 half, that staged/public-endpoint route is now live parameterized at `2%r / 32%r = 1%r / 16%r` rather than demo-bound.
- The parameterized route can now land back in the canonical game chain by paying an explicit budgeted bridge charge.

In practical theorem names, the strongest relevant current facts are:

- `d_ms_after_rom_observable_v2_eq_after_binding`
- `d_ms_after_rom_observable_v2_canonical`
- `L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure`
- `A_MS2_rom_programming_semantic_public_endpoint_transition_bound`
- `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound`
- `A_G0_to_G1_ms_parameterized_transition_bound`
- `qssm_main_theorem_parameterized_budget`

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

## Why The Blocker Is Semantic, Not Organizational

The missing piece is not a forgotten wrapper in the game layer.

- The owner surfaces already exist.
- The staged public-endpoint wrappers already exist.
- The LE parameterized route already closes to the top theorem surface.
- The MS parameterized route already closes as far as the public-endpoint composition layer.

What remains missing is a stronger lower theorem about the actual relationship between the public AfterRom carrier and the canonical AfterRom carrier that would remove or reduce the charged landing term.

## If Research Reopens Here

The first honest owner boundary is still below the theorem surface if future work wants to tighten the new route.

On the current tree, the live LE rejection and live LE FS `3%r / 32%r` lanes are already closed, and the MS1 canonical failure plus staged/public-endpoint lanes are now also live parameterized at `3%r / 32%r` and `1%r / 16%r`. The only remaining localized replay seam is therefore MS2 local failure comparison `ms_rom_local_failure_mass_le_parameterized_budget`, so the next focused audit is MS2 rather than another LE refinement or a theorem-surface mutation.

- Start at `ms/MSProbabilitySurface.ec` or a sibling lower companion.
- Do not start in `MainTheorem.ec`.
- Do not start by mutating theorem names.
- Do not start with a readability refactor.
- Do not treat the current gap as a packaging problem.

## Research Backlog

These items remain future research only.

- tighter public AfterRom to canonical AfterRom semantic reconciliation
- true production-count substitution
- removal of alias-based parameterized bridge equalities
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