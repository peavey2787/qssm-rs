# Security Instantiation Blocker Map

Navigation: [EasyCrypt README](../README.md)

## Status Summary

- `qssm_main_theorem_realworld_budget` is proved in `theorem/MainTheoremRealWorld.ec`.
- It is conditional on `qssm_realworld_obligations`, not a fully concrete theorem.
- `qssm_main_theorem_realworld_concrete_128` exists in `RealWorldBudgetInstantiation.ec`.
- `qssm_main_theorem_realworld_concrete_128_5_over_2_98` also exists in `RealWorldBudgetInstantiation.ec`.
- The concrete budget record `realworld_budget_concrete_128` is formalized.
- The concrete component epsilon is `1 / 2^98`.
- The concrete top epsilon is `5 / 2^98`.
- The closed form `5 / 2^98` is proved in EasyCrypt.
- Both concrete theorems remain conditional on four explicit component-bound premises.
- The current live lower actuals still collapse to the live toy parameterized masses, currently `3%r / 64%r` per component.
- Therefore component budgets such as `2^-98` cannot currently discharge the real-world obligations.

At the current May 2026 checkpoint, the real-world theorem surface has both an abstract upper-bound theorem and a concrete external-bound instantiation skeleton. The concrete instantiation is theorem-facing and machine-checked, but it still depends on four explicit component-bound premises rather than internally proved reductions.

## Theorem Surface

The real-world theorem surface currently lives in:

- `primitives/RealWorldBudgetParameters.ec`
- `primitives/RealWorldBudgetObligations.ec`
- `ms/MSProbabilitySurfaceRealWorld.ec`
- `le/LEStatisticalDistanceRealWorld.ec`
- `games/GameMSHopCompositionRealWorld.ec`
- `games/GameLEBridgeRealWorld.ec`
- `theorem/MainTheoremRealWorld.ec`
- `RealWorldBudgetInstantiation.ec`

The real-world budget record in `primitives/RealWorldBudgetParameters.ec` has four fields:

- `rwb_epsilon_ms_hash_binding`
- `rwb_epsilon_ms_rom_programmability`
- `rwb_epsilon_le_rej`
- `rwb_epsilon_le_fs`

These correspond to the four theorem-facing real-world budget components:

- MS1 hash binding
- MS2 ROM programmability
- LE rejection
- LE FS

The top-level real-world structure is additive and keeps the duplicate MS2 charge explicit:

```text
epsilon_top_realworld b =
  epsilon_ms_hash_binding_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_le_realworld b
```

with

```text
epsilon_le_realworld b =
  epsilon_le_rej_realworld b + epsilon_le_fs_realworld b
```

The exact obligation predicates in `primitives/RealWorldBudgetObligations.ec` are:

```text
le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual =
  epsilon_le_rej_actual <= epsilon_le_rej_realworld b /\
  epsilon_le_fs_actual <= epsilon_le_fs_realworld b

ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =
  epsilon_ms_hash_binding_actual <= epsilon_ms_hash_binding_realworld b /\
  epsilon_ms_rom_actual <= epsilon_ms_rom_programmability_realworld b

qssm_realworld_obligations b
  epsilon_le_rej_actual epsilon_le_fs_actual
  epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual /\
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual
```

The exact theorem statement in `theorem/MainTheoremRealWorld.ec` is:

```text
lemma qssm_main_theorem_realworld_budget
  (b : realworld_budget) (x : qssm_public_input) (s : seed) (D : distinguisher) :
  qssm_realworld_obligations b
    (le_rejection_parameterized_failure_probability x s)
    LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
    (ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x))
    (ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x)) =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    epsilon_ms_hash_binding_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_le_realworld b.
```

This theorem is proved. The point of this document is that it is not yet a concrete `lambda = 128` instantiation theorem.

The concrete external-bound instantiation layer in `RealWorldBudgetInstantiation.ec` now adds:

- `realworld_budget_concrete_128`
- `epsilon_ms_hash_binding_concrete_128`
- `epsilon_ms_rom_programmability_concrete_128`
- `epsilon_le_rej_concrete_128`
- `epsilon_le_fs_concrete_128`
- `epsilon_top_concrete_128_eq_5_over_2_98`
- `qssm_realworld_obligations_concrete_128_from_component_bounds`
- `qssm_main_theorem_realworld_concrete_128`
- `qssm_main_theorem_realworld_concrete_128_5_over_2_98`

Those theorems package a concrete budget record and a concrete top bound, but they still require four explicit component-bound premises. They do not claim that those four component reductions are internally proved in the current tree.

## Current Lower Actual Terms

The current lower actual terms referred to by the real-world obligations are:

- LE rejection actual: `le_rejection_parameterized_failure_probability x s`
- LE FS actual: `LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass`
- MS1 actual: `ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x)`
- MS2 actual: `ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x)`

Today each of those lower actuals collapses to the current live parameterized owner value `3%r / 64%r`.

- MS1: `epsilon_ms_hash_binding_parameterized = 3%r / 64%r`
- MS2: `epsilon_ms_rom_programmability_parameterized = 3%r / 64%r`
- LE rejection: `epsilon_le_rej_parameterized = 3%r / 64%r`
- LE FS: `epsilon_le_fs_parameterized = 3%r / 64%r`

So the currently reachable concrete routed sum is still:

```text
MS1 + MS2 + MS2 + LE_rej + LE_fs = 15%r / 64%r
```

This is why the current real-world theorem surface is honest as an abstract upper-bound theorem but is not yet a negligible concrete security theorem.

## Why `lambda = 128` Cannot Be Plugged In Yet

Suppose a future concrete instantiation proposes the placeholder component bound:

```text
epsilon_component = q * n * r * 2^-lambda
```

With `lambda = 128`, `q = 2^20`, `n = 2^10`, and `r = 1`, that placeholder budget is:

```text
epsilon_component = 2^-98
```

That does not discharge the current real-world obligations, because today the theorem is comparing those budget fields against current lower actuals that still collapse to `3%r / 64%r`.

The required inequality would therefore be:

```text
3%r / 64%r <= 2^-98
```

That inequality is false.

- `3 / 64 = 0.046875`
- `2^-98 ~= 3.1554436208840472e-30`

So the current blocker is not only missing arithmetic infrastructure. The immediate blocker is semantic: the present real-world theorem still ranges over the live toy lower masses.

## Worked Arithmetic For `lambda = 128`

This section records the worked arithmetic only. It does not claim that the bound is currently proved in EasyCrypt.

Use:

- `lambda = 128`
- `q = 2^20`
- `n = 2^10`
- `r = 1`

Placeholder component formula:

```text
epsilon_component = q * n * r * 2^-lambda
```

Then:

- `q * n * r = 2^20 * 2^10 * 1 = 2^30`
- `epsilon_component = 2^30 * 2^-128 = 2^-98`

The current top-level theorem structure is:

```text
epsilon_top = MS1 + 2 * MS2 + LE_rej + LE_fs
```

If all four component budgets are taken to be `2^-98`, then:

- `MS1 = 2^-98`
- `MS2 = 2^-98`, charged twice
- `LE_rej = 2^-98`
- `LE_fs = 2^-98`
- `epsilon_top = 5 * 2^-98`

Exact rational form:

```text
epsilon_top = 5 / 2^98
```

That is:

- `5 / 2^98 = 5 / 316912650057057350374175801344`
- decimal `~= 1.5777218104420236e-29`

Equivalent `2^-k` form:

```text
k = 98 - log2(5) ~= 95.67807190511263
```

So the placeholder arithmetic gives:

```text
epsilon_top = 2^-95.67807190511263
```

That arithmetic is now reflected in the concrete external-bound instantiation file: the component epsilon is packaged as `1 / 2^98`, the top epsilon is proved as `5 / 2^98`, and the concrete theorem remains conditional on four explicit component-bound premises.

## What Exists And What Is Still Missing For Concrete External-Bound Instantiation

The external-bound instantiation layer now exists explicitly in `RealWorldBudgetInstantiation.ec`.

What now exists:

- `RealWorldBudgetInstantiation.ec`
- `realworld_budget_concrete_128`
- `epsilon_ms_hash_binding_concrete_128`
- `epsilon_ms_rom_programmability_concrete_128`
- `epsilon_le_rej_concrete_128`
- `epsilon_le_fs_concrete_128`
- `qssm_realworld_obligations_concrete_128_from_component_bounds`
- `qssm_main_theorem_realworld_concrete_128`
- `qssm_main_theorem_realworld_concrete_128_5_over_2_98`

What is still missing:

- internally proved component reductions for the four concrete component-bound premises
- any theorem discharging those four premises from the current live `3%r / 64%r` lower actuals
- any weighted or non-uniform sampler semantics below the current real-world obligation surface

What the existing file already does:

- define the concrete component formulas
- package them into a concrete `realworld_budget` record
- derive `qssm_realworld_obligations` from explicit component-bound premises
- instantiate `qssm_main_theorem_realworld_budget` with that concrete record

The critical blocker is explicit:

- the four concrete component-bound premises are not internally proved in the current tree
- the current live `3%r / 64%r` lower actuals do not themselves satisfy the `1 / 2^98` concrete component budget
- if the component reductions are external to this EasyCrypt tree, they must appear as explicit premises, not axioms
- the current theorem surface already supports this architecture cleanly, because `qssm_main_theorem_realworld_budget` already packages the concrete top-level composition over explicit obligation predicates

In other words, the new concrete theorem surface exists, but it is still a theorem over explicit component-bound assumptions rather than a zero-premise internal reduction.

## Concrete External-Bound Instantiation Path

The intended external-bound path is sequential and does not require weighted sampler replay.

Step 1:

Add `RealWorldBudgetInstantiation.ec`. This step is now complete.

Step 2:

Define the concrete component formulas separately for:

- MS1
- MS2
- LE rejection
- LE FS

That should produce the concrete owner terms:

- `epsilon_ms_hash_binding_concrete_128`
- `epsilon_ms_rom_programmability_concrete_128`
- `epsilon_le_rej_concrete_128`
- `epsilon_le_fs_concrete_128`

Step 3:

Build `realworld_budget_concrete_128` from those four concrete component formulas. This step is now complete.

Step 4:

Add the arithmetic and nonnegativity lemmas needed for the concrete record. This step is now complete for the current `1 / 2^98` and `5 / 2^98` closed forms.

Step 5:

Introduce the component-bound inputs as explicit theorems or explicit premises.

If the component reductions remain external to the current EasyCrypt tree, the honest shape is:

- four explicit component-bound premises on the concrete theorem, or
- a separate theorem proving those premises and then a derived obligation theorem

Step 6:

Derive the concrete obligation bundle from those explicit component-bound inputs. This now exists as `qssm_realworld_obligations_concrete_128_from_component_bounds`.

Step 7:

Prove `qssm_main_theorem_realworld_concrete_128` by instantiating `qssm_main_theorem_realworld_budget` with `realworld_budget_concrete_128`. This step is now complete, together with the closed-form companion `qssm_main_theorem_realworld_concrete_128_5_over_2_98`.

This path yields a formal theorem over explicit component-bound assumptions while leaving weighted sampler replay out of scope.

## External-Bound Versus Internal Sampler Proof

There are two different targets.

### A. Concrete External-Bound Theorem

This path proves a concrete top theorem over explicit component-bound premises.

- define concrete component formulas from `lambda`, `q`, `n`, and `r`
- state or prove the required component inequalities as explicit theorem premises
- instantiate `qssm_main_theorem_realworld_budget` over a concrete record

This path can yield a concrete theorem over externally justified operational caps without modeling weighted or non-uniform sampler internals.

### B. Fully Internal Sampler Theorem

This path models the weighted or non-uniform samplers themselves and proves the component failure probabilities internally.

- add a weighted finite-support replay layer
- prefer normalized per-component category weights
- add constructive weighted distribution definitions
- add weighted event-mass lemmas
- replay the current lower live sampler mass proofs over that weighted layer

This is the missing path for `100%` formal sampler semantics.

The distinction is important:

- external-bound instantiation can give a concrete theorem over explicit component-bound premises
- internal weighted-sampler replay is what is needed for a fully internal sampler model

## Recommended Next Implementation Options

### Option A: Concrete External-Bound Theorem

- add `RealWorldBudgetInstantiation.ec`
- define concrete component formulas
- define `realworld_budget_concrete_128`
- state `qssm_main_theorem_realworld_concrete_128` with four explicit component-bound premises if those reductions remain external

This is the recommended next step if the goal is a concrete theorem over externally justified operational caps.

### Option B: Internal Weighted Sampler Model

- add a weighted category-owner layer
- start with an LE rejection weighted pilot
- replay the lower live sampler proofs over weighted finite-support distributions

This is the correct next step only if sampler-internal weighted semantics must be formalized.

Recommendation:

- start with Option A if the goal is a concrete theorem over externally justified operational caps
- start with Option B only if sampler-internal weighted semantics must be formalized

## Caveats

- weighted or non-uniform sampler internals are still not modeled
- the current lower route still uses the frozen `3%r / 64%r` live owners
- the duplicate MS2 charge remains explicit
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- this document does not claim fully internal weighted-sampler verification

## Current Bottom Line

- `qssm_main_theorem_realworld_budget` exists and is proved.
- `qssm_main_theorem_realworld_concrete_128` exists and is proved.
- `qssm_main_theorem_realworld_concrete_128_5_over_2_98` exists and is proved.
- The current lower actuals still collapse to `3%r / 64%r` per component.
- Therefore the placeholder bound `2^-98` cannot currently discharge the obligations.
- The worked arithmetic for `lambda = 128`, `q = 2^20`, `n = 2^10`, `r = 1` gives `epsilon_component = 2^-98`, which is packaged concretely as `1 / 2^98`, and `epsilon_top = 5 / 2^98 ~= 2^-95.67807190511263`.
- The closed form `5 / 2^98` is now proved in EasyCrypt.
- The concrete theorem still remains conditional on four explicit component-bound premises.