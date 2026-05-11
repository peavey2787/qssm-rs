# QSSM Formal Verification Summary

QSSM is an EasyCrypt formalization of the QSSM theorem stack, covering the exact-zero abstraction route, the semantic-budget companion route, the frozen parameterized route, and a concrete real-world `lambda = 128` companion route with explicit external reduction obligations. This page is the release-facing entrypoint for experienced formal methods engineers and cryptographers; the detailed architecture, assumptions, audit notes, and route-by-route references now live under [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md), [docs/FORMAL_THEOREM_MAP.md](docs/FORMAL_THEOREM_MAP.md), and [docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md](docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md).

## Formal Verification Status

- `149` EasyCrypt theories checked
- `0` axioms
- `0` admits
- worktree clean at the current freeze checkpoint
- fully reproducible via [check_easycrypt.sh](check_easycrypt.sh)

## Top-Level Theorems

- [theorem/MainTheorem.ec](theorem/MainTheorem.ec): `qssm_main_theorem` for the exact-zero abstraction route
- [theorem/MainTheorem.ec](theorem/MainTheorem.ec): `qssm_main_theorem_semantic_budget` for the semantic-budget companion route
- [theorem/MainTheoremParameterized.ec](theorem/MainTheoremParameterized.ec): `qssm_main_theorem_parameterized_budget = 15%r / 64%r`
- [RealWorldBudgetInstantiation.ec](RealWorldBudgetInstantiation.ec): `qssm_main_theorem_realworld_concrete_128_with_all_reductions`
- [RealWorldBudgetInstantiation.ec](RealWorldBudgetInstantiation.ec): `qssm_main_theorem_realworld_concrete_128_with_all_reductions_5_over_2_98`

## Formal Verification Summary

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): formal verification architecture and file-map overview
- [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md): theorem assumptions and modeling boundaries
- [docs/FORMAL_THEOREM_MAP.md](docs/FORMAL_THEOREM_MAP.md): theorem inventory, route map, and charged-route caveats
- [docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md](docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md): protocol-spec versus EasyCrypt conformance audit
- [../../CONCRETE_128_REDUCTION_FREEZE.md](../../CONCRETE_128_REDUCTION_FREEZE.md): stable, audit-ready release boundary for the concrete all-reductions checkpoint

## Reproducibility

```bash
cd formal-verification/easycrypt
./check_easycrypt.sh
```

The checker runs the EasyCrypt files in dependency order and reproduces the current `149`-theory, `0`-axiom, `0`-admit baseline.

## Concrete `lambda = 128` Theorem Summary

The concrete all-reductions theorem route closes in [RealWorldBudgetInstantiation.ec](RealWorldBudgetInstantiation.ec) with component epsilon `1 / 2^98`, top epsilon `5 / 2^98`, and effective security of approximately `95.67807190511263` bits. It is reduction-facing on LE rejection, LE FS, MS1, and MS2; the duplicate MS2 charge remains explicit; and public AfterRom remains budget-close to canonical AfterRom rather than zero-equal. Full theorem-route details and caveats live in [docs/FORMAL_THEOREM_MAP.md](docs/FORMAL_THEOREM_MAP.md).

Reduction-facing premises:

- LE rejection reduction obligation
- LE FS reduction obligation
- MS1 reduction obligation
- MS2 reduction obligation

## Verification Boundary

- protocol-level EasyCrypt model fully verified at the current checkpoint
- weighted or non-uniform sampler internals are not modeled
- external reductions remain explicit external obligations
- no machine-checked refinement link to the Rust implementation exists today

## Directory Map

```text
easycrypt/
├── check_easycrypt.sh
├── docs/
├── primitives/
├── ms/
├── le/
├── sim/
├── games/
├── theorem/
├── RealWorldBudgetInstantiation.ec
└── docs/plans/
```

## Pointers to Deep Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): architecture and file-map details
- [docs/ASSUMPTIONS.md](docs/ASSUMPTIONS.md): theorem assumptions and modeling boundaries
- [docs/FORMAL_THEOREM_MAP.md](docs/FORMAL_THEOREM_MAP.md): theorem inventory and route map
- [docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md](docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md): protocol-spec conformance audit
- [docs/plans/](docs/plans): historical proof-plan notes