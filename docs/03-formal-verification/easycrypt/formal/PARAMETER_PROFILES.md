# Parameter Profiles

Navigation: [EasyCrypt README](../README.md)

## Purpose

This document is a design-only layer for future concrete parameter selection on the now-closed canonical parameterized theorem route.

It does not change any EasyCrypt constants, does not mutate `ParameterizedBudgetParameters.ec`, does not mutate `BudgetParameters.ec`, and does not change any theorem statement.

## Current Proven Symbolic Top Budget

The current closed top-level parameterized theorem is `theorem/MainTheoremParameterized.ec : qssm_main_theorem_parameterized_budget`.

Its proven symbolic budget is:

```text
epsilon_ms_hash_binding_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_ms_rom_programmability_parameterized
+ epsilon_le_parameterized
```

For planning purposes, it is convenient to name the same slots as:

```text
epsilon_MS1 := epsilon_ms_hash_binding_parameterized
epsilon_MS2 := epsilon_ms_rom_programmability_parameterized
epsilon_LE_rej := epsilon_le_rej_parameterized
epsilon_LE_fs := epsilon_le_fs_parameterized
epsilon_LE := epsilon_le_parameterized
```

Then the theorem-level expression is:

```text
epsilon_LE = epsilon_LE_rej + epsilon_LE_fs

epsilon_top_parameterized =
  epsilon_MS1 + 2 * epsilon_MS2 + epsilon_LE
```

No concrete production values are selected in this document. Any future rational examples should be labeled illustrative only and not yet production-selected.

## Why The MS2 Charge Appears Twice

The duplicated `epsilon_ms_rom_programmability_parameterized` term is real and must remain explicit.

- First MS2 charge: the staged public AfterRom route still pays the parameterized MS2 ROM-programming transition on the public-endpoint lane.
- Second MS2 charge: the route then pays a separate budgeted public AfterRom to canonical AfterRom landing.
- The second charge is not a formatting artifact and should not be simplified away in theorem prose.
- Public AfterRom is still budget-close to canonical AfterRom, not zero-equal, so the second charge cannot be hidden behind a zero-cost identification.

## Profile Classes

This document uses four planning classes for future concrete parameter selection.

### Demo Profile

Use case: maintain continuity with the current demo-compatible parameterized proof surface while planning eventual non-demo substitution.

- MS1 hash-binding parameterized budget: `epsilon_MS1_demo`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_demo`
- LE rejection parameterized budget: `epsilon_LE_rej_demo`
- LE FS parameterized budget: `epsilon_LE_fs_demo`
- LE umbrella parameterized budget: `epsilon_LE_demo = epsilon_LE_rej_demo + epsilon_LE_fs_demo`
- Full canonical parameterized top budget: `epsilon_top_demo = epsilon_MS1_demo + 2 * epsilon_MS2_demo + epsilon_LE_demo`

Design note: this profile is the closest conceptual match to the currently checked alias-compatible parameterized route.

### Conservative Profile

Use case: choose intentionally loose parameter margins before any production-count substitution is attempted.

- MS1 hash-binding parameterized budget: `epsilon_MS1_conservative`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_conservative`
- LE rejection parameterized budget: `epsilon_LE_rej_conservative`
- LE FS parameterized budget: `epsilon_LE_fs_conservative`
- LE umbrella parameterized budget: `epsilon_LE_conservative = epsilon_LE_rej_conservative + epsilon_LE_fs_conservative`
- Full canonical parameterized top budget: `epsilon_top_conservative = epsilon_MS1_conservative + 2 * epsilon_MS2_conservative + epsilon_LE_conservative`

Design note: this profile is useful when the goal is honest slack rather than tightness.

### Production Candidate Profile

Use case: represent the intended post-substitution parameter surface once actual counts and non-alias lower bridge proofs exist.

- MS1 hash-binding parameterized budget: `epsilon_MS1_prod`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_prod`
- LE rejection parameterized budget: `epsilon_LE_rej_prod`
- LE FS parameterized budget: `epsilon_LE_fs_prod`
- LE umbrella parameterized budget: `epsilon_LE_prod = epsilon_LE_rej_prod + epsilon_LE_fs_prod`
- Full canonical parameterized top budget: `epsilon_top_prod = epsilon_MS1_prod + 2 * epsilon_MS2_prod + epsilon_LE_prod`

Design note: this profile should not be presented as active until the production-count substitution checklist below is complete.

### Stress-Test Profile

Use case: exercise theorem plumbing and sensitivity analysis under intentionally amplified parameter choices.

- MS1 hash-binding parameterized budget: `epsilon_MS1_stress`
- MS2 ROM-programming parameterized budget: `epsilon_MS2_stress`
- LE rejection parameterized budget: `epsilon_LE_rej_stress`
- LE FS parameterized budget: `epsilon_LE_fs_stress`
- LE umbrella parameterized budget: `epsilon_LE_stress = epsilon_LE_rej_stress + epsilon_LE_fs_stress`
- Full canonical parameterized top budget: `epsilon_top_stress = epsilon_MS1_stress + 2 * epsilon_MS2_stress + epsilon_LE_stress`

Design note: this profile is for robustness and readability testing, not for a public security claim.

## Slot Template For Any Future Concrete Profile

Any concrete profile should fill the same slot template.

| Slot | Symbolic owner | Profile-specific placeholder |
|---|---|---|
| MS1 hash-binding | `epsilon_ms_hash_binding_parameterized` | `epsilon_MS1_*` |
| MS2 ROM-programming | `epsilon_ms_rom_programmability_parameterized` | `epsilon_MS2_*` |
| LE rejection | `epsilon_le_rej_parameterized` | `epsilon_LE_rej_*` |
| LE FS | `epsilon_le_fs_parameterized` | `epsilon_LE_fs_*` |
| LE umbrella | `epsilon_le_parameterized` | `epsilon_LE_* = epsilon_LE_rej_* + epsilon_LE_fs_*` |
| Full canonical top budget | theorem-level sum | `epsilon_top_* = epsilon_MS1_* + 2 * epsilon_MS2_* + epsilon_LE_*` |

The `*` placeholder stands for `demo`, `conservative`, `prod`, or `stress`.

## Production-Count Substitution Checklist

Before any profile is promoted from design to theorem-facing parameter selection, complete the following work:

1. Choose actual counts for the parameterized MS1, MS2, LE rejection, and LE FS owners.
2. Prove or replace the current alias-compatible lower bridge lemmas with real non-alias parameterized bridge proofs.
3. Preserve the owner-layer parameterized arithmetic so theorem statements continue to consume the same budget structure.
4. Rerun the full EasyCrypt checker and the zero-axiom / zero-admit validation.
5. Update theorem-facing and release-facing docs after the new counts and bridge proofs are locked.

## Explicit Warning About The Current Proof Surface

The current parameterized proof route is structurally complete, but many bridge lemmas still rely on alias-compatibility with demo counts until production-count substitution is performed.

That means the architecture and theorem composition are now in place, but future concrete parameter selection still requires lower-proof replacement work before any production-count claim is honest.

## MS2 Refactor Candidates Before Production-Count Substitution

This phase does not refactor the MS2 route. The items below are audit targets for later only.

Potential audit targets:

- `ms/MSProbabilitySurfaceParameterized.ec`
- `ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec`
- `games/GameAdvantageParameterized.ec`
- `games/GameMSHopCompositionParameterized.ec`

Questions for a later readability pass:

- Can the duplicated MS2 charge be factored into a named `epsilon_ms_rom_programmability_parameterized_canonical_landing` term?
- Can theorem readability improve without hiding the second MS2 charge?
- Can bridge lemmas be renamed to make the first MS2 charge versus the landing MS2 charge clearer?

No such refactor is implemented here. This document records the audit boundary only.