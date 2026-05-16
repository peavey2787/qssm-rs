# Concrete 256 All-Reductions Freeze

This note freezes the May 2026 EasyCrypt checkpoint for the concrete `lambda = 256` all-reductions theorem route. The repeated concrete composition is intentionally left in place for this release because factoring it now would risk obscuring the explicitly duplicated MS2 charge while adding little proof value after the theorem already closes cleanly.

## Checkpoint Summary

- `qssm_main_theorem_realworld_concrete_256_with_all_reductions` closes.
- `qssm_main_theorem_realworld_concrete_256_with_all_reductions_5_over_2_226` closes.
- checker snapshot: `OK: checked 149 theories`
- `axiom_count=0`
- `admit_count=0`

## Bound Summary

- component epsilon: `1 / 2^226`
- top epsilon: `5 / 2^226`
- equivalent bit level: approximately `223.67807190511263`

## Reduction-Facing Premises

- LE rejection reduction obligation
- LE FS reduction obligation
- MS1 reduction obligation
- MS2 reduction obligation

## Caveats

- the four reduction obligations are explicit theorem premises, not axioms
- weighted or non-uniform sampler internals are not modeled
- the duplicate MS2 charge remains explicit
- public AfterRom remains budget-close to canonical AfterRom, not zero-equal
- the original concrete theorem pair remains unchanged
- no theorem claims the frozen toy component actuals are `<= 2^-226`

## Freeze Decision

- do not factor the concrete composition in this release
- revisit factoring only if a later presentation still preserves the explicit MS2 duplication visibly

## Status

This checkpoint is the recommended stopping point for the current concrete external-bound theorem family. The theorem closes, the closed-form companion closes, the theorem-facing caveats remain explicit, and no additional proof engineering is required for this release checkpoint.