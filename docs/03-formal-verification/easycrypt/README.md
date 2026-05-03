# EasyCrypt Skeleton (Phase 1)

This directory contains the **initial EasyCrypt scaffold only**.

> **Warning:** This is **not** a completed machine-checked security proof. All high-level statements are either abstract operators or explicit axioms until lemmas are proved and axioms removed.

## Scope

- Phase 1 target: checker-ready syntax, explicit interfaces, and named axiomatized proof obligations.
- No completed end-to-end proof chain yet.
- No Rust logic changes are implied by these files.
- MS-3c concrete payload/seed constructor architecture (to shrink comparison axioms) is outlined in **`plans/MS_3c_proof_plan.md`** section **“Concrete MS-3c payload constructor design (architecture)”**.

## Installing EasyCrypt (for this repo)

EasyCrypt may not be in `PATH` on all hosts. Install it locally before running the check script.

**Recommended (official):** use [OPAM](https://opam.ocaml.org/) as documented upstream:

1. Install and initialize OPAM (see [OPAM install guide](https://opam.ocaml.org/doc/Install.html)).
2. Create/activate a dedicated switch (optional but recommended).
3. Pin and install EasyCrypt:

   ```bash
   opam pin -yn add easycrypt https://github.com/EasyCrypt/easycrypt.git
   opam install --deps-only easycrypt
   opam install alt-ergo.2.6.0
   opam install easycrypt
   ```

4. Configure Why3 for SMT solvers:

   ```bash
   easycrypt why3config
   ```

Full detail and alternatives (Nix, from source): [EasyCrypt `INSTALL.md`](https://github.com/EasyCrypt/easycrypt/blob/main/INSTALL.md) and [Setting up EasyCrypt](https://easycrypt.gitlab.io/easycrypt-web/docs/guides/setting-up-easycrypt/).

**Repo allowlist:** see `../easycrypt-import-allowlist.md` for which Rust/spec artifacts are in scope for formalization.

## How to run the checker

From a Unix-like shell (Git Bash, WSL, Linux, macOS), in **this directory**:

```bash
chmod +x check_easycrypt.sh   # once, if needed
./check_easycrypt.sh
```

Or with an explicit binary path:

```bash
EASYCRYPT=/path/to/easycrypt ./check_easycrypt.sh
```

The script type-checks theories in dependency order. Each file is checked with `easycrypt compile -R . <path>` so that theories in subfolders are resolved by **basename** (theory name equals the filename without `.ec`). Imports use those basenames (for example `require import QssmTypes FS.`).

**Order (see `check_easycrypt.sh`):**

1. `primitives/Domains.ec`
2. `primitives/QssmTypes.ec` (named `QssmTypes` to avoid clashing with the EasyCrypt prelude theory `Types`)
3. `primitives/Algebra.ec`
4. `primitives/FS.ec`
5. `ms/SchnorrBranch.ec`
6. `ms/BitnessOne.ec`
7. `ms/BitnessVector.ec`
8. `ms/TranscriptObservable.ec`
9. `ms/true_clause/TrueClauseTypes.ec`
10. `ms/true_clause/TrueClauseMSB.ec`
11. `ms/true_clause/TrueClauseTheorem.ec`
12. `ms/TrueClause.ec` (facade)
13. `ms/comparison/ComparisonTypes.ec`
14. `ms/comparison/ComparisonDigests.ec`
15. `ms/comparison/ComparisonPayloadTypes.ec`
16. `ms/comparison/ComparisonPayloadSeedTypes.ec`
17. `ms/comparison/ComparisonPayloadFromSeed.ec`
18. `ms/comparison/ComparisonPayloadSeedAnchors.ec`
19. `ms/comparison/ComparisonPayloadSeeds.ec` (facade: re-exports 16–18)
20. `ms/comparison/ComparisonPayloadSupportTypes.ec`
21. `ms/comparison/ComparisonPayloadSupportPublic.ec`
22. `ms/comparison/ComparisonPayloadSupportShares.ec`
23. `ms/comparison/ComparisonPayloadSupport.ec` (facade)
24. `ms/comparison/ComparisonPayloadFalseClause.ec`
25. `ms/comparison/ComparisonPayload.ec` (facade)
26. `ms/comparison/ComparisonCouplingTypes.ec`
27. `ms/comparison/ComparisonCouplingAxioms.ec`
28. `ms/comparison/ComparisonCouplingMarginals.ec`
29. `ms/comparison/ComparisonCouplingSchedule.ec`
30. `ms/comparison/ComparisonCouplingTheorem.ec` (facade)
31. `ms/comparison/ComparisonCoupling.ec` (facade)
32. `ms/comparison/ComparisonTheorem.ec`
33. `ms/Comparison.ec` (facade)
34. `ms/SourceModel.ec` (MS-3a observable frame: abstract transcript ops, pack, digest helpers; abstract **`ms3a_public_*`** spine projections + **`ms3a_public_{bitness,transcript}_shape_ok`** from `ms_public_input`)
35. `ms/source/SourceTypes.ec`
36. `ms/source/SourceConstructors.ec` (constructors + Phase-1 **`ms3a_phase1_{real,sim}_payload_from_public_input`** from **`ms3a_public_*`**; imports **`SourceModel`**)
37. `ms/source/SourcePayloadDistributions.ec` (payload seed + `dmap` payload laws)
38. `ms/source/SourceCouplingTypes.ec` (MS-3a joint seed law: `dmap` of abstract spine `d_ms3a_seed_spine_joint` + coupled predicate + projection ops)
39. `ms/source/SourceCouplingAxioms.ec` (marginal-bridge documentation + definitional unfold)
40. `ms/source/SourceCouplingTheorem.ec` (spine preimage, `dmap_comp` projection folds, pair-relation from WF on spine support, layer-map lemmas)
41. `ms/source/SourceBitnessDistributions.ec` (bitness-layer `dmap` + `dmap_comp` folds)
42. `ms/source/SourceDistributionLemmas.ec` (support / constructor-image / payload-pair helpers)
43. `ms/source/SourceObservableDistributions.ec` (observable pushforwards + layer bridge)
44. `ms/source/SourceDistributions.ec` (facade: `require export` of payload, **`SourceCouplingTheorem`**, bitness, distribution lemmas, observable)
45. `ms/source/SourceExecutionLink.ec` (standalone MS-3a execution/public-spine boundary: predicate `ms3a_execution_public_spine_link` packages the two remaining programmed bridges without changing current imports)
46. `ms/source/SourceProgrammedObligations.ec`
47. `ms/source/SourcePublicFieldObligations.ec` (paired-public axioms + **`L_ms3a_seed_pair_*_when_seeds_are_phase1`** conditional spine lemmas)
48. `ms/source/SourceScheduleSeed.ec` (lemma `A_ms3a_bitness_layer_seed_schedule` + `L_ms3a_bitness_layer_seed_schedule_composed_form`)
49. `ms/source/SourceSchedulePayload.ec` (payload `dmap` schedule, `ms3a_ax_*` from payload support, `ms3a_payload_schedule_equivalence`)
50. `ms/source/SourceScheduleTheorem.ec` (`ms3a_source_eq_from_bitness_layer`, constructor-scoped lemmas)
51. `ms/source/SourceScheduleObligations.ec` (facade: `require export` of the three schedule modules)
52. `ms/source/SourceObligations.ec` (facade)
53. `ms/source/SourceTheorem.ec`
54. `ms/MS.ec`
55. `le/LESurface.ec`
56. `le/LESetB.ec`
57. `le/LERejection.ec`
58. `le/LEFsProgramming.ec`
59. `le/LEViewIndist.ec`
60. `le/LEStatisticalDistance.ec`
61. `le/LEHVZK.ec`
62. `le/LEModel.ec` (facade)
63. `sim/Simulator.ec`
64. `games/GameTypes.ec`
65. `games/GameViews.ec`
66. `games/GameAdvantage.ec`
67. `games/GameMSHopTypes.ec`
68. `games/GameMSHopTransitions.ec`
69. `games/GameMSHopComposition.ec`
70. `games/GameMSHops.ec` (facade)
71. `games/GameLEBridge.ec`
72. `games/Games.ec` (facade)
73. `theorem/MainTheorem.ec`
72. `theorem/MainTheorem.ec`

If your EasyCrypt build exposes the binary as `ec` instead of `easycrypt`, the script falls back automatically when `easycrypt` is missing.

**Single-file check (top of the stack):**

```bash
cd docs/03-formal-verification/easycrypt
easycrypt compile -R . theorem/MainTheorem.ec
```

## Layout (directories)

```
docs/03-formal-verification/easycrypt/
├── README.md
├── check_easycrypt.sh
├── primitives/
│   ├── Domains.ec
│   ├── QssmTypes.ec
│   ├── Algebra.ec
│   └── FS.ec
├── ms/
│   ├── SchnorrBranch.ec
│   ├── BitnessOne.ec
│   ├── BitnessVector.ec
│   ├── TranscriptObservable.ec
│   ├── true_clause/
│   │   ├── TrueClauseTypes.ec
│   │   ├── TrueClauseMSB.ec
│   │   └── TrueClauseTheorem.ec
│   ├── TrueClause.ec
│   ├── comparison/
│   │   ├── ComparisonTypes.ec
│   │   ├── ComparisonDigests.ec
│   │   ├── ComparisonPayloadTypes.ec
│   │   ├── ComparisonPayloadSeedTypes.ec
│   │   ├── ComparisonPayloadFromSeed.ec
│   │   ├── ComparisonPayloadSeedAnchors.ec
│   │   ├── ComparisonPayloadSeeds.ec   (facade)
│   │   ├── ComparisonPayloadSupportTypes.ec
│   │   ├── ComparisonPayloadSupportPublic.ec
│   │   ├── ComparisonPayloadSupportShares.ec
│   │   ├── ComparisonPayloadSupport.ec
│   │   ├── ComparisonPayloadFalseClause.ec
│   │   ├── ComparisonPayload.ec
│   │   ├── ComparisonCouplingTypes.ec
│   │   ├── ComparisonCouplingAxioms.ec
│   │   ├── ComparisonCouplingMarginals.ec
│   │   ├── ComparisonCouplingSchedule.ec
│   │   ├── ComparisonCouplingTheorem.ec
│   │   ├── ComparisonCoupling.ec
│   │   └── ComparisonTheorem.ec
│   ├── Comparison.ec
│   ├── SourceModel.ec
│   ├── source/
│   │   ├── SourceTypes.ec
│   │   ├── SourceConstructors.ec
│   │   ├── SourcePayloadDistributions.ec
│   │   ├── SourceCouplingTypes.ec
│   │   ├── SourceCouplingAxioms.ec
│   │   ├── SourceCouplingTheorem.ec
│   │   ├── SourceBitnessDistributions.ec
│   │   ├── SourceDistributionLemmas.ec
│   │   ├── SourceObservableDistributions.ec
│   │   ├── SourceDistributions.ec (facade)
│   │   ├── SourceProgrammedObligations.ec
│   │   ├── SourcePublicFieldObligations.ec
│   │   ├── SourceScheduleSeed.ec
│   │   ├── SourceSchedulePayload.ec
│   │   ├── SourceScheduleTheorem.ec
│   │   ├── SourceScheduleObligations.ec (facade)
│   │   ├── SourceObligations.ec
│   │   └── SourceTheorem.ec
│   └── MS.ec
├── le/
│   ├── LESurface.ec
│   ├── LESetB.ec
│   ├── LERejection.ec
│   ├── LEFsProgramming.ec
│   ├── LEViewIndist.ec
│   ├── LEStatisticalDistance.ec
│   ├── LEHVZK.ec
│   └── LEModel.ec
├── sim/
│   └── Simulator.ec
├── games/
│   ├── GameTypes.ec
│   ├── GameViews.ec
│   ├── GameAdvantage.ec
│   ├── GameMSHopTypes.ec
│   ├── GameMSHopTransitions.ec
│   ├── GameMSHopComposition.ec
│   ├── GameMSHops.ec
│   ├── GameLEBridge.ec
│   └── Games.ec
├── theorem/
│   └── MainTheorem.ec
└── plans/
    ├── MS_3a_proof_plan.md
    ├── MS_3b_proof_plan.md
    ├── MS_3c_proof_plan.md
    ├── LE_HVZK_proof_plan.md
    └── G0_G1_G2_game_plan.md
```

## File map (legacy Qssm* names → current paths)

| Former root file | Current location |
|------------------|-------------------|
| `QssmDomains.ec` | `primitives/Domains.ec` |
| `QssmTypes.ec` | `primitives/QssmTypes.ec` (theory `QssmTypes`; see note above) |
| `QssmFS.ec` | `primitives/FS.ec` |
| `QssmSchnorrSingleBit.ec` | `primitives/Algebra.ec` + `ms/SchnorrBranch.ec` |
| `QssmMSBitnessSingle.ec` | `ms/BitnessOne.ec` |
| `QssmMSBitnessVector.ec` | `ms/BitnessVector.ec` |
| `QssmMSTranscriptObservable.ec` | `ms/TranscriptObservable.ec` |
| `QssmMSTrueClause.ec` | `ms/TrueClause.ec` (facade) + `ms/true_clause/TrueClause{Types,MSB,Theorem}.ec` |
| `QssmMSComparison.ec` | `ms/Comparison.ec` (facade) + `ms/comparison/*.ec` split modules |
| `QssmMS.ec` (bulk) | `ms/SourceModel.ec` + `ms/source/*.ec` (split MS-3a material) |
| `QssmMS.ec` (façade: hash binding + MS-3c wrapper) | `ms/MS.ec` |
| `QssmLE.ec` | `le/LEModel.ec` (facade) + `le/LESurface.ec` … `le/LEHVZK.ec` |
| `QssmSim.ec` | `sim/Simulator.ec` |
| `QssmGames.ec` | `games/Games.ec` (facade) + `games/Game*.ec` split modules |
| `QssmTheorem.ec` | `theorem/MainTheorem.ec` |

## Admitted / axiomatized placeholders (Phase 1)

- **ROM / programmability (A2 surface):** `primitives/FS.ec` — `A2_ms_rom_programmability_nonneg`, `A2_programmable_oracle_exists`
- **MS:** `ms/SourceModel.ec` and **`ms/source/`** still carry the MS-3a source scaffold: **`d_ms3a_real_payload_seed`** remains abstract, **`d_ms3a_sim_payload_seed`** remains the definitional joint-sim marginal, and the source-facing proof surface still exposes the three spine axioms in **`SourcePayloadDistributions.ec`** together with proved schedule/public-field lemmas.
- **MS:** `SourceExecutionLink.ec` remains the source-facing execution/public-spine boundary. **`SourcePublicBitnessConstructors.ec`** now fixes the concrete list-level constructor boundary on `ms3a_bitness_layer_source`, via **`ms3a_public_bits_of_execution`** and definitionally mapped **`ms3a_public_bitness_globals_of_execution`**. **`SourcePublicBitnessExecution.ec`** still centralizes the ROM/FS public-bitness semantic debt in the single package axiom **`A_ms3a_public_bitness_execution`**, and **`SourceRealExecutionSeed.ec`** now carries only the bridge axiom **`A_ms3a_real_payload_seed_matches_execution_seed`** while proving **`ms3a_real_execution_seed_link_of_game_execution`**. The former programmed-layer axiom names in `SourceProgrammedObligations.ec` remain lemmas, and the net named MS-3a axiom count is still **5**.
**Status C:** **`A_ms3a_real_seed_bitness_fields_are_public_on_support`** also remains unchanged. The real seed record has the needed fields directly, but support of **`d_ms3a_real_payload_seed`** is abstract, so membership never exposes a constructor, a phase-1 payload equality, or a spine preimage without reopening the already-blocked real marginal story. This phase was therefore a wiring audit only, and no local constructor/projection collapse was available.
**Status R:** **`A_ms3a_public_payload_bitness_programmed`** and **`A_ms3a_real_seed_bitness_fields_are_public_on_support`** no longer remain as standalone MS-3a axioms. `SourceProgrammedObligations.ec` now proves both names as lemmas, using the execution-seed bridge/package lemmas exported by `SourceRealExecutionSeed.ec`.
**Execution/public-payload linkage status:** the remaining programmed/public-spine semantic debt is now centralized in **`ms/source/SourcePublicBitnessExecution.ec`**, not spread across `SourceProgrammedObligations.ec`. The concrete boundary law **`d_ms3a_real_execution_public_seed`**, the bridge axiom **`A_ms3a_real_payload_seed_matches_execution_seed`**, and the single public-bitness package axiom **`A_ms3a_public_bitness_execution`** are the only MS-3a execution/public-spine assumptions needed to recover the old theorem shapes downstream.
**Real execution-seed boundary:** `SourceRealExecutionSeed.ec` now proves **`ms3a_real_execution_seed_link_of_game_execution`** from the new public-bitness boundary together with the concrete GameLink source/seed lemmas. The file still bridges execution seeds back to the old abstract real law through **`A_ms3a_real_payload_seed_matches_execution_seed`**, and still exports the theorem-shape lemmas **`ms3a_public_payload_bitness_programmed_of_execution_seed_law`**, **`ms3a_real_seed_public_fields_on_support_of_execution_seed_law`**, and **`ms3a_execution_public_spine_link_of_execution_seed_law`**. Net named MS-3a axiom count remains **5**: the three spine axioms in **`SourcePayloadDistributions.ec`** plus **`A_ms3a_real_payload_seed_matches_execution_seed`** and **`A_ms3a_public_bitness_execution`**.
**Real-seed wiring audit:** the bridge keeps **`d_ms3a_real_payload_seed`** as the exact-distribution surface seen by **`SourceBitnessDistributions.ec`**, **`SourceScheduleSeed.ec`**, and **`SourceCouplingTypes.ec`**, while support/projection consumers use the proved execution-seed theorem through `SourceProgrammedObligations.ec`. No import cycle was introduced when `SourceProgrammedObligations.ec` imported `SourceRealExecutionSeed.ec`; the next non-local step is to replace **`A_ms3a_public_bitness_execution`** or the bridge axiom **`A_ms3a_real_payload_seed_matches_execution_seed`** with concrete execution/game semantics rather than re-open source-local rewrites.
- **LE:** split under `le/` — `LESurface.ec` (core ops, `epsilon_le`, views, surrogates, game-hop / sdist surface, Set-B and hiding predicates), `LESetB.ec` (Set-B lemmas + `A_LE_{real,sim}_view_distribution_defined`), `LERejection.ec` (rejection layer + `A_LE_rejection_surrogate_sdist_bound` / half-bound), `LEFsProgramming.ec` (FS layer + `A_LE_fs_surrogate_preserves_shape` / `A_LE_fs_surrogate_sdist_bound`), `LEViewIndist.ec` (view indistinguishability + distribution links), `LEStatisticalDistance.ec` (triangle / distinguisher bridge + `A_LE_view_advantage_bound_from_indistinguishability`), `LEHVZK.ec` (`A_LE_real_sim_transcript_equiv_bound`, `A_LE_SetB_HVZK_bound`, `A_LE_HVZK_transition_bound`); **`le/LEModel.ec`** is a thin facade that imports the chain so `require import LEModel` pulls lemmas from the split modules. Theories that use LE **operators** (for example `le_game_hop_adv`, `le_transcript_observable`) also **`require import LESurface`** before `LEModel`, because EasyCrypt does not re-export transitive imports into the client scope. Same named axioms/lemmas and semantics as before the split.
- **LE bridge interface:** `games/GameLEBridge.ec` keeps a single non-crypto boundary axiom `A_game_pr_LE_projection_semantics` (generic `game_pr` agrees with LE projected probability for `G1`/`G2` via `game_pr_le_projected`).
- **Simulator:** `sim/Simulator.ec` — `simulate_qssm_transcript_public_only`
- **Types / games:** `primitives/QssmTypes.ec` defines `ms_game_stage`, `ms_game_view_record`, and `game_view` (`GV_ms` vs `GV_g2_full_sim`). The game layer is now split under `games/`: `GameTypes.ec` (MS view helpers/stage predicates), `GameViews.ec` (G0/G1/G2 and `G_MS_*` constructors), `GameAdvantage.ec` (`game_pr`, `Adv`, `Adv_*`, arithmetic lemmas), `GameMSHops.ec` (MS1..MS3c transition axioms/lemmas + composed `A_G0_to_G1_ms_transition_bound`), and `GameLEBridge.ec` (LE view/projector bridge, projected-adv lemmas, `A_G1_to_G2_le_transition_bound`). `Games.ec` is a thin facade importing those split modules; theorem-facing names remain unchanged.
- **Theorem:** `theorem/MainTheorem.ec` — non-negativity placeholders `A1_ms_hash_binding`, `A2_ms_rom_programmability`, `A4_le_hvzk`, bridge lemmas `use_MS_3a` / `use_MS_3b` / `use_MS_3c`, and proved additive game-hop lemma `qssm_main_theorem_skeleton` over `Adv_G0_G2_QSSM`

- **Single-branch MS-3a (`ms/SchnorrBranch.ec` + `primitives/Algebra.ec`):** `MS_3a_single_branch_schnorr_reparam` is fully proved (no `admit`). Root Schnorr-layer assumption is **`duni_scalar_shift_reparam`** on `duni_scalar`.

- **Checker note:** there is **no** `admit` remaining in any `*.ec` file under this directory; open items are **named axioms** only (see each theory).

## Next proof target

**MS-3a source obligations (file split):** `d_ms3a_*` sampling laws and related lemmas are split under **`ms/source/`** — **`SourcePayloadDistributions.ec`** (abstract spine joint + real marginal / WF / paired-public-support **axioms**; **sim** seed law **defined** as joint sim marginal), **`SourceBitnessDistributions.ec`**, **`SourceDistributionLemmas.ec`**, **`SourceObservableDistributions.ec`**, re-exported by facade **`SourceDistributions.ec`** (theory name **`SourceDistributions`** unchanged). Seed programming and packaged lemmas live in **`SourceProgrammedObligations.ec`**; paired public fields and payload-support bridges in **`SourcePublicFieldObligations.ec`**; schedule material is split across **`SourceScheduleSeed.ec`** (**lemma** **`A_ms3a_bitness_layer_seed_schedule`**), **`SourceSchedulePayload.ec`** (payload **`dmap`** schedule **`A_ms3a_payload_dmap_bitness_layer_schedule`**, `ms3a_ax_*` from support), **`SourceScheduleTheorem.ec`** (**`ms3a_source_eq_from_bitness_layer`**, constructor-scoped lemmas), re-exported by facade **`SourceScheduleObligations.ec`**. **`SourceObligations.ec`** is a thin **`require export`** facade (imports may still use theory **`SourceObligations`**).

**Execution/link boundary:** **`SourceExecutionLink.ec`** remains the standalone source-facing boundary for the remaining MS-3a execution/public-spine story. It defines predicate **`ms3a_execution_public_spine_link`** and the proved projection lemmas **`ms3a_public_payload_bitness_programmed_of_execution_link`** and **`ms3a_real_seed_public_fields_on_support_of_execution_link`**; `SourcePayloadDistributions.ec` remains below it to avoid cycles.
**Concrete boundary on top:** **`SourceRealExecutionGameLink.ec`** now provides the minimal concrete execution/game-link objects: deterministic public source **`ms3a_game_public_bitness_source`**, point-mass source sampler **`d_ms3a_real_execution_bitness_source`**, and concrete seed law **`d_ms3a_real_execution_public_seed`** implemented as `dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer`. The structural local lemmas on that boundary are proved, and the semantic public-bitness corollaries now close as well: **`ms3a_game_public_bits_per_bit_programmed`**, **`ms3a_game_public_bitness_globals_ordered`**, and **`ms3a_game_public_spine_programmed`** are all derived from **`SourcePublicBitnessExecution.ec`**. **`SourcePublicBitnessConstructors.ec`** now records the concrete list-level constructor surface over `ms3a_bitness_layer_source`, but it is still only a skeleton boundary: **`A_ms3a_public_bitness_execution`** remains unchanged until a future theorem **`ms3a_public_bitness_execution_of_game_execution`** bridges those constructors back to the abstract public spine. Imports stay acyclic: **`SourcePublicBitnessExecution.ec`** sits between `SourceExecutionLink.ec` and `SourceRealExecutionGameLink.ec`, and **`SourceRealExecutionSeed.ec`** now proves **`ms3a_real_execution_seed_link_of_game_execution`** instead of axiomatizing it. The residual semantic debt is now the single public-bitness package axiom **`A_ms3a_public_bitness_execution`** plus the real-seed bridge axiom **`A_ms3a_real_payload_seed_matches_execution_seed`**.

The concrete objects added in this phase are:

- **`ms3a_game_public_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source`** — deterministic execution/public-spine source carrying stmt, bits, bitness globals, comparison global, and transcript digest in one place, rather than another abstract wrapper around `ms3a_public_*`.
- **`d_ms3a_real_execution_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source distr`** — concrete real execution sampler shape at the source-record layer, currently the canonical public-spine point mass.
- **`d_ms3a_real_execution_public_seed`** — now defined as `dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer`.

The remaining local lemmas/theorems are:

- **`ms3a_game_public_bitness_source_projects_public_spine`** — concrete source projects to `ms3a_public_stmt_digest`, `ms3a_public_bits`, `ms3a_public_bitness_globals`, and `ms3a_public_transcript_digest`.
- **`ms3a_game_public_bits_per_bit_programmed`** and **`ms3a_game_public_bitness_globals_ordered`** — the concrete per-bit FS/ROM facts needed to discharge `ms_per_bit_programmed` and `ms_ordered_challenge_vector_matches`.
- **`ms3a_real_execution_public_seed_support_inv`** — support inversion for the `dmap`-implemented real execution seed law.
- **`ms3a_real_execution_bitness_source_public_fields_on_support`** — concrete source support matches the same public stmt / bits / bitness globals.

Current game files are still too abstract to discharge the remaining assumptions directly: `MS.ec` / `GameViews.ec` / `GameMSHopTransitions.ec` continue to use `witness` for the MS observable, `Simulator.ec` exposes only abstract `ms_simulator` / `extract_ms_public`, and `GameAdvantage.ec` is only about abstract `game_pr` arithmetic. The new source-side public-bitness boundary isolates that gap in **`SourcePublicBitnessExecution.ec`**, while **`SourcePublicBitnessConstructors.ec`** now provides the list-level constructor surface the future theorem should use. Because `SourceModel.ec` sits above `ms/source/` in the current dependency order, the safe next patch is to keep **`ms3a_public_*`** abstract and add a single equality bridge to the constructor surface rather than make those projections definitional from below.

1. **MS-3a (residual)** — discharge the **source** axiom bundle (still **three** axioms: **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**) plus the **two** remaining execution/public-spine axioms: **`A_ms3a_real_payload_seed_matches_execution_seed`** in **`SourceRealExecutionSeed.ec`** and **`A_ms3a_public_bitness_execution`** in **`SourcePublicBitnessExecution.ec`**. **`ms3a_real_execution_seed_link_of_game_execution`** is now a **proved theorem**, and **`A_ms3a_public_payload_bitness_programmed`**, **`A_ms3a_real_seed_bitness_fields_are_public_on_support`**, and **`A_ms3a_sim_seed_bitness_fields_are_public_on_support`** remain **proved lemmas** downstream of it. The immediate next target is therefore no longer the GameLink corollaries; it is replacing the new public-bitness package axiom or the real-seed bridge axiom with concrete execution/game semantics. The current constructor design is to keep `SourceModel.ec` abstract and add a single equality bridge from **`ms3a_public_bits`** / **`ms3a_public_bitness_globals`** to the concrete **`ms3a_public_*_of_execution`** surface, because `SourceModel.ec` sits above `ms/source/` in the current import order. The four `A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support` names remain **proved lemmas** packaged by **`A_ms3a_{real,sim}_seed_programmed_on_support`**; instantiate abstract **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from execution/games (**`d_ms3a_sim_payload_seed`** is already the joint sim marginal **by definition**; lemma **`A_ms3a_spine_sim_marginal_matches_seed`** is proved); payload **`ms3a_*_payload_from_seed`** is definitional identity on payload-shaped seeds; the four **`A_ms3a_seed_pair_*_source_shared`** facts and **`A_ms3a_bitness_layer_seed_schedule`** are already **proved lemmas** at the abstract interface; **`A_ms3a_seed_pair_public_fields_on_support`** is already a **proved lemma**; see `plans/MS_3a_proof_plan.md`.
2. **MS-3b** — discharge axiom **`A_ms3b_operand_hdb_implies_value_gt_target`** (narrow value/target `nth` leaf); lemma **`A_ms3b_operand_hdb_implies_msb_first_strict_gt`** (**`ms3b_msb_first_strict_gt_at`**) is **proved** from it. Lemma **`A_ms3b_comparison_semantics`** projects the axiom; **`A_ms3b_hdb_implies_value_one_target_zero`** is definitional on **`ms3b_value_gt_target_at`**. Tie **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`** to transcript / execution material in **`ms/true_clause/`** (via theory **`TrueClause`**, facade **`ms/TrueClause.ec`**); see `plans/MS_3b_proof_plan.md`.

Then: MS-3c comparison lane in **`ms/Comparison.ec`** / **`ms/comparison/`** (`plans/MS_3c_proof_plan.md`; **`d_ms3c_real_sim_payload_coupling`** is the **product** of the payload laws; each payload law is a **`dmap`** of **`d_ms3c_{real,sim}_payload_seed`**, itself the **product** of **Phase-1** **`dunit tt`** on **`unit`** for all four seed components (real/sim challenge and real/sim announcement); **`L_ms3c_{real,sim}_payload_seed_lossless`** and **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** are **proved** from **`dprod_ll_auto`** / **`dmap_ll`** and the four component losslessness lemmata (**`L_ms3c_{real,sim}_seed_challenge_lossless`**, **`L_ms3c_real_seed_announcement_lossless`**, **`L_ms3c_sim_seed_announcement_lossless`**); Phase-1 **`ms3c_phase1_payload_from_public_input`** (surfaced as **`ms3c_{real,sim}_payload_from_seed`**) wires public clause indices and false-branch list lengths from **`ms3c_public_*`**; the four **`A_ms3c_{real,sim}_from_seed_uses_{public_indices,share_length}`** facts are **proved lemmas** in **`ComparisonPayloadSeedAnchors.ec`** (re-exported by facade **`ComparisonPayloadSeeds.ec`**; **`L_ms3c_{real,sim}_seed_index_shape_valid`**, **`L_ms3c_{real,sim}_seed_length_shape_valid`** still package schedule/transcript bridges). **`ms3c_obs_*`** remains scaffolding for transcript-backed fields; Phase-1 **`mscp_query_digest`** is **`ms_comparison_query_digest (ms3c_public_stmt_digest x) (ms3c_clause_ann_digests_from_surface …)`** (canonical statement digest **`ms3c_public_stmt_digest`**; announcement digest helpers live in **`ComparisonTypes.ec`**). Lemma **`A_ms3c_clause_surface_query_digest_constructed`** is **proved** (no `forall stmt`); surface bounds (**`A_ms3c_surface_query_digest_field_correct`**, **`A_ms3c_query_digest_statement_bound`**, etc.) now assume **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**. Marginal equality of **`d_ms3c_coupling_{real,sim}_projection`** vs standalone laws is **proved** from **`Distr`** given those lemmas; **`A_ms3c_coupling_pair_relation`** is a **proved** lemma in **`ComparisonCouplingSchedule.ec`** (marginal **`ms3c_ax_payload_*`** facts on joint payload support ⇒ pointwise **`ms3c_real_sim_payload_coupled`** via **`supp_dprod`** and digest list agreement); **`ComparisonCouplingAxioms.ec`** has **no** coupling fragment **axioms**: all **`A_ms3c_payload_*_match`** hooks are **proved lemmata** from **`L_ms3c_cross_support_real_sim_payload_equal`**. **`ms/comparison/*`** is **axiom-free**; the MS-3c **game** gap is axiom **`A_MS3c_comparison_bundle_implies_game_pr_equality`** (**`games/GameMSHopTypes.ec`**: bundle ⇒ **`game_pr`** equality on **`G_MS_after_comparison`** vs **`G_MS_sim`**). Lemma **`A_MS3c_canonical_comparison_exact_bound`** (same **`Adv … <= 0%r`** statement) is **proved** there from **`Adv_def`**; false-announcement support on payload support is **proved** (**`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** as **lemmata** in **`ComparisonPayloadFalseClause.ec`**, from Phase-1 **`map sch_pubkey`** wiring and **`L_ms_false_clause_simulated_phase1_from_public_input`**). **`ms3c_ax_payload_announcements_match_shape`** is unconditional via **`L_ms3c_ax_payload_announcements_match_shape_total`** in **`ComparisonPayloadSupportPublic.ec`** (re-exported by **`ComparisonPayloadSupport.ec`**); **`ms3c_ax_payload_announcement_digests_preserved`** follows from **`ms3c_ax_payload_public_fields_match`** via **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** in **`ComparisonCouplingSchedule.ec`**; projection and marginal packaging lemmas live in **`ComparisonCouplingMarginals.ec`**; **`A_ms3c_payload_schedule_eq_from_coupling`** is a **proved** lemma in **`ComparisonCouplingSchedule.ec`** (re-exported by **`ComparisonCouplingTheorem.ec`** / **`ComparisonCoupling.ec`**). Payload support uses the four proved from_seed anchor lemmas (**`A_ms3c_{real,sim}_from_seed_uses_share_length`**, **`A_ms3c_{real,sim}_from_seed_uses_public_indices`**, with **`L_ms3c_{real,sim}_seed_length_shape_valid`**) and derives support-shape as lemmas (**`A_ms3c_{real,sim}_payload_support_length_index_shapes`**) via `supp_dmap`, then uses proved **`L_ms3c_{real,sim}_payload_support_simulatable`**; announcement list shape on payloads is **proved** (**`L_ms3c_*_payload_ann_digest_list_shape_ok`**). False-clause path uses proved constructor lemmas **`L_ms3c_{real,sim}_constructor_false_index_nonempty`** (**`ms3c_public_false_branch_nonempty`** + public-index anchors + **`ms3c_public_shape_ok`**), placeholder **`L_ms3c_public_false_branch_nonempty_placeholder`** (`ComparisonTypes.ec` singleton false-branch placeholders), seed-level wrappers (**`A_ms3c_{real,sim}_seed_false_index_nonempty`**), proved support lemmata **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** (false announcements vs **`sch_pubkey`** of false shares on support, Phase-1 constructor), and proved **`L_ms3c_false_clause_generation_on_support`** (**`ms3c_ax_payload_false_clauses_simulated`**); false-announcement nonempty is proved as lemmas (**`A_ms3c_real_seed_false_clause_nonempty`**, **`A_ms3c_sim_seed_false_clause_nonempty`**), and **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** / **`A_ms3c_false_clause_simulation`** remain proved lemmas. Query digest: proved ann projection lemmas (**`L_ms3c_ann_digest_projection_correct`**, **`L_ms3c_ann_digests_alias`**), proved lemma **`A_ms3c_clause_surface_query_digest_constructed`** (Phase-1 payload, canonical **`ms3c_public_stmt_digest x`**), proved lemmas **`A_ms3c_surface_query_digest_field_correct`** / **`A_ms3c_query_digest_statement_bound`** (require **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**), **`L_ms3c_query_digest_uses_ann_digest_projection`**, **`L_ms3c_query_digest_ordered_announcements_bound`**, **`L_ms3c_query_digest_statement_bound_hash`**, same-announcement lemmas **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`** (same **`x`** / Phase-1 payload hypothesis), and packaging **`L_ms3c_digest_announcement_only`** ( **`Hann`** is redundant with **`L_ms3c_ann_digest_list_shape`**). On the game layer, discharge canonical MS1 bound **`A_MS1_canonical_hash_binding_bound`** as a lemma layered over narrower hash-binding obligations **`A_MS1_hash_binding_surface_defined`**, **`A_MS1_hash_binding_bad_event_bounded`**, and **`A_MS1_hash_binding_replacement_advantage_bound`**; discharge canonical MS2 bound **`A_MS2_canonical_rom_programming_bound`** as a lemma layered over narrower ROM obligations **`A_MS2_rom_query_surface_defined`**, **`A_MS2_rom_programmed_points_bounded`**, and **`A_MS2_rom_reprogramming_advantage_bound`**; keep **`A_MS3a_canonical_bitness_exact_bound`** and **`A_MS3b_canonical_true_clause_bound`** as canonical **axioms**; for MS3c keep **`A_MS3c_comparison_bundle_implies_game_pr_equality`** as the remaining **axiom**, with **`A_MS3c_canonical_comparison_exact_bound`** a **proved lemma**. Generic step-wrapper axioms were removed, because canonical bounds on fixed `G_MS_*` views do not by themselves imply bounds for all arbitrary step-related `src`/`dst` views without an additional `Adv`-invariance theory over frozen observable/public fields. On LE, discharge **`A_LE_rejection_surrogate_sdist_bound`**, **`A_LE_fs_surrogate_sdist_bound`**, **`A_LE_rejection_surrogate_preserves_shape`**, **`A_LE_fs_surrogate_preserves_shape`** (and instantiate **`le_post_rejection_surrogate`** / **`le_fs_view_surrogate`**) from concrete rejection/FS distribution analysis alongside the remaining rejection/FS axiom bundles (`plans/LE_HVZK_proof_plan.md`); instantiate or relate **`le_distinguisher_event`** when bridging to concrete games; keep **`A_game_pr_LE_projection_semantics`** as the exact LE bridge/interface boundary until `game_pr` is concretized (`plans/G0_G1_G2_game_plan.md`).

## Syntax / checker notes

- Theories are loaded by **basename** under this tree with `easycrypt compile -R . <file>`.
- Trivial placeholder axioms often use the proposition `true` (not `True`). MS-3a’s global lemma targets **`ms3a_bitness_real_sim_equiv`** (distribution equality on `ms_transcript_observable`). MS-3b’s **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`** are no longer the literal **`true`** hooks (see **`ms/TrueClause.ec`** facade and **`ms/true_clause/`**).
- `DOMAIN_MS` is fixed to match `truth-engine/qssm-utils/src/hashing.rs` (not invented).
