# EasyCrypt Skeleton (Phase 1)

This directory contains the **initial EasyCrypt scaffold only**.
It is intentionally proof-light and uses explicit axioms/placeholders to pin interfaces before full formal proofs.

## Scope

- Phase 1 target: clean, reviewable formalization structure.
- No completed end-to-end proof chain yet.
- No Rust logic changes are implied by these files.

## Files

- `QssmDomains.ec`
- `QssmTypes.ec`
- `QssmFS.ec`
- `QssmMS.ec`
- `QssmLE.ec`
- `QssmSim.ec`
- `QssmGames.ec`
- `QssmTheorem.ec`

## Admitted / axiomatized placeholders in Phase 1

- ROM abstraction and programmability placeholders (A2 surface) in `QssmFS.ec`
- MS v2 placeholders:
  - `MS_3a_exact_bitness_simulation`
  - `MS_3b_true_clause_characterization`
  - `MS_3c_exact_comparison_simulation`
  in `QssmMS.ec`
- LE Set B / A4 placeholder in `QssmLE.ec`
- Game-transition skeleton placeholders in `QssmGames.ec`
- Main theorem skeleton axiom in `QssmTheorem.ec`

## Next proof targets (ordered)

1. MS-3a exact bitness simulation
2. MS-3b true-clause characterization
3. MS-3c exact comparison simulation
4. `G0 -> G1`
5. `G1 -> G2`
6. Final additive theorem

## Validation note

If EasyCrypt is installed locally, run the checker across all `.ec` files.
If EasyCrypt is unavailable, perform syntax-oriented sanity checks and keep placeholders explicit.
