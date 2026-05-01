# EasyCrypt Skeleton (Phase 1)

This directory contains the **initial EasyCrypt scaffold only**.

> **Warning:** This is **not** a completed machine-checked security proof. All high-level statements are either abstract operators or explicit axioms until lemmas are proved and axioms removed.

## Scope

- Phase 1 target: checker-ready syntax, explicit interfaces, and admitted placeholders.
- No completed end-to-end proof chain yet.
- No Rust logic changes are implied by these files.

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
9. `ms/TrueClause.ec`
10. `ms/comparison/ComparisonTypes.ec`
11. `ms/comparison/ComparisonDigests.ec`
12. `ms/comparison/ComparisonPayloads.ec`
13. `ms/comparison/ComparisonCouplingTypes.ec`
14. `ms/comparison/ComparisonCouplingAxioms.ec`
15. `ms/comparison/ComparisonCouplingTheorem.ec`
16. `ms/comparison/ComparisonCoupling.ec` (facade)
17. `ms/comparison/ComparisonTheorem.ec`
18. `ms/Comparison.ec` (facade)
19. `ms/SourceModel.ec` (MS-3a observable frame: abstract transcript ops, pack, digest helpers)
20. `ms/source/SourceTypes.ec`
21. `ms/source/SourceConstructors.ec`
22. `ms/source/SourceDistributions.ec`
23. `ms/source/SourceObligations.ec`
24. `ms/source/SourceTheorem.ec`
25. `ms/MS.ec`
26. `le/LEModel.ec`
27. `sim/Simulator.ec`
28. `games/GameTypes.ec`
29. `games/GameViews.ec`
30. `games/GameAdvantage.ec`
31. `games/GameMSHopTypes.ec`
32. `games/GameMSHopTransitions.ec`
33. `games/GameMSHopComposition.ec`
34. `games/GameMSHops.ec` (facade)
35. `games/GameLEBridge.ec`
36. `games/Games.ec` (facade)
37. `theorem/MainTheorem.ec`

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
│   ├── TrueClause.ec
│   ├── comparison/
│   │   ├── ComparisonTypes.ec
│   │   ├── ComparisonDigests.ec
│   │   ├── ComparisonPayloads.ec
│   │   ├── ComparisonCouplingTypes.ec
│   │   ├── ComparisonCouplingAxioms.ec
│   │   ├── ComparisonCouplingTheorem.ec
│   │   ├── ComparisonCoupling.ec
│   │   └── ComparisonTheorem.ec
│   ├── Comparison.ec
│   ├── SourceModel.ec
│   ├── source/
│   │   ├── SourceTypes.ec
│   │   ├── SourceConstructors.ec
│   │   ├── SourceDistributions.ec
│   │   ├── SourceObligations.ec
│   │   └── SourceTheorem.ec
│   └── MS.ec
├── le/
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
| `QssmMSTrueClause.ec` | `ms/TrueClause.ec` |
| `QssmMSComparison.ec` | `ms/Comparison.ec` (facade) + `ms/comparison/*.ec` split modules |
| `QssmMS.ec` (bulk) | `ms/SourceModel.ec` + `ms/source/*.ec` (split MS-3a material) |
| `QssmMS.ec` (façade: hash binding + MS-3c wrapper) | `ms/MS.ec` |
| `QssmLE.ec` | `le/LEModel.ec` |
| `QssmSim.ec` | `sim/Simulator.ec` |
| `QssmGames.ec` | `games/Games.ec` (facade) + `games/Game*.ec` split modules |
| `QssmTheorem.ec` | `theorem/MainTheorem.ec` |

## Admitted / axiomatized placeholders (Phase 1)

- **ROM / programmability (A2 surface):** `primitives/FS.ec` — `A2_ms_rom_programmability_nonneg`, `A2_programmable_oracle_exists`
- **MS:** `ms/SourceModel.ec` — abstract observable frame (pack / digest / alignment); **`ms/source/`** — structured source types, constructors, `d_ms3a_*` laws; **remaining MS-3a payload debt** = three support/public obligations (`ms3a_payload_real_support_programmed`, `ms3a_payload_sim_support_programmed`, `ms3a_payload_pair_public_fields_on_support`) **plus** one **unconditional** payload pushforward equality (**`A_ms3a_payload_dmap_bitness_layer_schedule`**); proved **`ms3a_ax_*`** layer lemmas; legacy compatibility wrapper **`ms3a_payload_schedule_equivalence`** (prefer the schedule axiom or **`ms3a_source_eq_from_bitness_layer`** for new work); **`MS_3a_exact_bitness_simulation`**; `ms/MS.ec` — `epsilon_ms_hash_binding`, **`ms1_hash_binding_step`**, **`ms2_rom_programming_step`**, **`ms3a_bitness_exact_step`**, **`ms3b_true_clause_exact_step`** (MS3b: same MS-3b forall bundle as the old game axiom + frozen `GV_ms`, `AfterBitness`→`AfterComparison`; **`Algebra`**, **`List`**, **`TrueClause`** in scope), `A1_ms_hash_binding_nonneg`, **`MS_3c_exact_comparison_simulation`** (wrapper over `ms/Comparison.ec`). ROM budget **`epsilon_ms_rom_programmability`** lives in **`primitives/FS.ec`** with **`A2_ms_rom_programmability_nonneg`** and **`A2_programmable_oracle_exists`**. **MS-3b** in **`ms/TrueClause.ec`** (structural **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`**; proved **`A_ms3b_bit_decomposition_correct`** / **`A_ms3b_pedersen_opening_correct`**; axiom **`A_ms3b_highest_differing_bit_correct`**). **MS-3c** in **`ms/Comparison.ec`** — comparison payloads (`d_ms3c_{real,sim}_comparison_payload`), `dmap` schedules, **proved** **`A_ms3c_payload_schedule_equiv`** from a narrower coupling/scheduling layer (`ms3c_real_sim_payload_coupled`, explicit coupling projections `d_ms3c_coupling_{real,sim}_projection`, `ms3c_ax_payload_support_coupling`, and coupling/marginal axioms) plus component payload obligations (see `plans/MS_3c_proof_plan.md`), proved schedule bridge, surface clause laws; **ordered announcement digest list** is **`ms3c_clause_ann_digests_from_surface`** (true then false branch digests via **`ms_single_bit_branch_digest`**), with **`A_ms3c_digest_announcement_only`** stating programmed **`mscc_query_digest`** against that projection only, and true-clause bridge **`A_ms3c_true_clause_from_ms3b_and_schnorr`** now proved from explicit MS-3b hook (`ms3c_true_clause_uses_ms3b_blinder_point`) plus Schnorr reparam readiness (`ms3c_true_clause_reparam_ready` / `MS_3a_single_branch_schnorr_reparam`).
- **LE:** `le/LEModel.ec` — non-vacuous `set_b_parameter_well_formed` / `le_set_b_params_ok`, `A4_le_hvzk_bound_nonneg`, LE hop carrier `le_game_hop_adv`, `le_view_statistical_distance` as `sdist` on `d_le_{real,sim}_view` (`require SDist`), `d_le_post_rejection_view` **defined** as `dmap (d_le_real_view x s) le_post_rejection_surrogate` and `d_le_sim_view` as `dmap (d_le_post_rejection_view x s) le_fs_view_surrogate` with abstract `le_post_rejection_surrogate` / `le_fs_view_surrogate`, abstract `le_distinguisher_event` with `le_view_distinguish_pr d D = mu d (le_distinguisher_event D)`, packaging `le_view_distinguishing_adv` / `le_view_statistical_distance_bound`, transcript predicate `le_real_sim_transcript_equiv`, and layered predicates `le_rejection_sampling_bound_ok`, `le_fs_programming_bound_ok`, `le_hvzk_bound`; **proved** Set-B unpackaging (`le_set_b_ring_dimension_valid`, `le_set_b_challenge_size_valid`, `le_set_b_norm_bounds_valid`, `le_set_b_eta_gamma_relation_valid`, lemmas `A_LE_SetB_ring_dimension_valid` … `A_LE_SetB_params_sound`, `L_LE_set_b_params_sound_implies_ok`); rejection-sampling obligations `A_LE_rejection_distribution_defined`, `A_LE_rejection_acceptance_probability_bounded`, `A_LE_rejection_output_shape_preserved`, axiom `A_LE_rejection_surrogate_preserves_shape`, proved `A_LE_rejection_witness_hiding_statistical_bound` / `A_LE_rejection_surrogate_hides_witness` / chain lemmas; LE FS/ROM obligations `A_LE_fs_query_surface_defined`, `A_LE_fs_programmable_oracle_available`, `A_LE_fs_programming_preserves_transcript_shape`, axiom `A_LE_fs_surrogate_preserves_shape`, proved `A_LE_fs_programming_cost_bounded_by_epsilon_le`; proved view distribution lemmas `A_LE_real_view_distribution_defined`, `A_LE_sim_view_distribution_defined`; proved view indistinguishability packaging `L_LE_combined_hiding_implies_view_indist`, `A_LE_real_sim_view_indistinguishable_from_bound_ok`, `A_LE_real_sim_view_indistinguishable`; axioms `A_LE_rejection_surrogate_sdist_bound`, `A_LE_fs_surrogate_sdist_bound`; proved `A_LE_post_rejection_to_sim_distribution_link`, `A_LE_rejection_half_sdist_bound`, `A_LE_fs_half_sdist_bound`, `A_LE_real_to_post_rejection_distribution_link`, `A_LE_rejection_contributes_to_sdist`, `A_LE_fs_contributes_to_sdist`, `A_LE_combined_hiding_bounds_sdist` (`sdist_triangle` + `ler_add`), `A_LE_view_indist_to_sd_bound`; proved `A_LE_distinguisher_event_probability_bounded_by_sdist` (`SDist.sdist_upper_bound` + `RealOrder`) and proved `A_LE_sd_bound_to_adv_bound` (wrapper); proved `A_LE_projected_advantage_matches_view_distance` and `A_LE_view_advantage_bound_from_indistinguishability`; derived lemmas `A_LE_rejection_sampling_hiding_bound`, `A_LE_fs_programming_bound`, `A_LE_real_sim_transcript_equiv_bound`, `A_LE_SetB_HVZK_bound`; wrapper lemma `A_LE_HVZK_transition_bound`
- **LE bridge interface:** `games/GameLEBridge.ec` keeps a single non-crypto boundary axiom `A_game_pr_LE_projection_semantics` (generic `game_pr` agrees with LE projected probability for `G1`/`G2` via `game_pr_le_projected`).
- **Simulator:** `sim/Simulator.ec` — `simulate_qssm_transcript_public_only`
- **Types / games:** `primitives/QssmTypes.ec` defines `ms_game_stage`, `ms_game_view_record`, and `game_view` (`GV_ms` vs `GV_g2_full_sim`). The game layer is now split under `games/`: `GameTypes.ec` (MS view helpers/stage predicates), `GameViews.ec` (G0/G1/G2 and `G_MS_*` constructors), `GameAdvantage.ec` (`game_pr`, `Adv`, `Adv_*`, arithmetic lemmas), `GameMSHops.ec` (MS1..MS3c transition axioms/lemmas + composed `A_G0_to_G1_ms_transition_bound`), and `GameLEBridge.ec` (LE view/projector bridge, projected-adv lemmas, `A_G1_to_G2_le_transition_bound`). `Games.ec` is a thin facade importing those split modules; theorem-facing names remain unchanged.
- **Theorem:** `theorem/MainTheorem.ec` — non-negativity placeholders `A1_ms_hash_binding`, `A2_ms_rom_programmability`, `A4_le_hvzk`, bridge lemmas `use_MS_3a` / `use_MS_3b` / `use_MS_3c`, and proved additive game-hop lemma `qssm_main_theorem_skeleton` over `Adv_G0_G2_QSSM`

- **Single-branch MS-3a (`ms/SchnorrBranch.ec` + `primitives/Algebra.ec`):** `MS_3a_single_branch_schnorr_reparam` is fully proved (no `admit`). Root Schnorr-layer assumption is **`duni_scalar_shift_reparam`** on `duni_scalar`.

- **Checker note:** there is **no** `admit` remaining in any `*.ec` file under this directory; open items are **named axioms** only (see each theory).

## Next proof target

1. **MS-3a (residual)** — discharge the three payload support/public axioms and **`A_ms3a_payload_dmap_bitness_layer_schedule`** in `ms/source/SourceObligations.ec` from concrete `d_ms3a_{real,sim}_source_payload` definitions; see `plans/MS_3a_proof_plan.md`.
2. **MS-3b** — discharge axiom **`A_ms3b_hdb_implies_value_one_target_zero`** (true-clause bit pattern at the highest-differing index; **`A_ms3b_highest_differing_bit_correct`** is now a proved lemma built from it) and (optionally) tie **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`** to transcript / execution material in `ms/TrueClause.ec`; see `plans/MS_3b_proof_plan.md`.

Then: shrink MS-3c axioms in **`ms/Comparison.ec`** (`plans/MS_3c_proof_plan.md`; **`d_ms3c_real_sim_payload_coupling`** is the **product** of the payload laws; each payload law is a **`dmap`** of **`d_ms3c_{real,sim}_payload_seed`**, itself the **product** of abstract challenge and announcement component samplers; **`L_ms3c_{real,sim}_payload_seed_lossless`** and **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** are **proved** from **`dprod_ll_auto`** / **`dmap_ll`** and four narrow axioms **`A_ms3c_{real,sim}_seed_{challenge,announcement}_lossless`**; marginal equality of **`d_ms3c_coupling_{real,sim}_projection`** vs standalone laws is **proved** from **`Distr`** given those lemmas; **`A_ms3c_coupling_pair_relation`** remains the scheduling bridge on joint support; **`A_ms3c_payload_schedule_eq_from_coupling`** is a **proved** lemma in **`ComparisonCouplingTheorem.ec`**). Payload support uses four narrow seed-shape axioms (**`A_ms3c_{real,sim}_seed_{length,index}_shape_valid`**) and derives support-shape as lemmas (**`A_ms3c_{real,sim}_payload_support_length_index_shapes`**) via `supp_dmap`, then uses proved **`L_ms3c_{real,sim}_payload_support_simulatable`**; announcement list shape on payloads is **proved** (**`L_ms3c_*_payload_ann_digest_list_shape_ok`**). False-clause path now uses two constructor-level false-index nonempty axioms (**`A_ms3c_real_constructor_false_index_nonempty`**, **`A_ms3c_sim_constructor_false_index_nonempty`**) with seed-level wrappers proved as lemmas (**`A_ms3c_real_seed_false_index_nonempty`**, **`A_ms3c_sim_seed_false_index_nonempty`**), and one support-local generation axiom (**`A_ms3c_false_clause_generation_on_support`**); false-announcement nonempty is proved as lemmas (**`A_ms3c_real_seed_false_clause_nonempty`**, **`A_ms3c_sim_seed_false_clause_nonempty`**), and **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** / **`A_ms3c_false_clause_simulation`** remain proved lemmas. Query digest: proved ann projection lemmas (**`L_ms3c_ann_digest_projection_correct`**, **`L_ms3c_ann_digests_alias`**), axiom **`A_ms3c_query_digest_statement_bound`** ( **`ms_comparison_query_digest`** in **`primitives/FS.ec`** ), proved **`L_ms3c_query_digest_uses_ann_digest_projection`** (alias), **`L_ms3c_query_digest_ordered_announcements_bound`**, **`L_ms3c_query_digest_statement_bound_hash`**, same-announcement lemmas **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`**, and packaging **`L_ms3c_digest_announcement_only`** ( **`Hann`** is redundant with **`L_ms3c_ann_digest_list_shape`**). On the game layer, discharge canonical axioms **`A_MS1_canonical_hash_binding_bound`**, **`A_MS2_canonical_rom_programming_bound`**, **`A_MS3a_canonical_bitness_exact_bound`**, **`A_MS3b_canonical_true_clause_bound`**, and **`A_MS3c_canonical_comparison_exact_bound`** from concrete games tied to the same hop budgets/hypotheses, while keeping the generic step bounds **`A_MS1_hash_binding_replacement_bound`**, **`A_MS2_rom_programming_replacement_bound`**, **`A_MS3a_bitness_exact_step_bound`**, **`A_MS3b_true_clause_exact_step_bound`**, and **`A_MS3c_comparison_exact_step_bound`** as compatibility wrappers for generic `src`/`dst` step APIs; on LE, discharge **`A_LE_rejection_surrogate_sdist_bound`**, **`A_LE_fs_surrogate_sdist_bound`**, **`A_LE_rejection_surrogate_preserves_shape`**, **`A_LE_fs_surrogate_preserves_shape`** (and instantiate **`le_post_rejection_surrogate`** / **`le_fs_view_surrogate`**) from concrete rejection/FS distribution analysis alongside the remaining rejection/FS axiom bundles (`plans/LE_HVZK_proof_plan.md`); instantiate or relate **`le_distinguisher_event`** when bridging to concrete games; keep **`A_game_pr_LE_projection_semantics`** as the exact LE bridge/interface boundary until `game_pr` is concretized (`plans/G0_G1_G2_game_plan.md`).

## Syntax / checker notes

- Theories are loaded by **basename** under this tree with `easycrypt compile -R . <file>`.
- Trivial placeholder axioms often use the proposition `true` (not `True`). MS-3a’s global lemma targets **`ms3a_bitness_real_sim_equiv`** (distribution equality on `ms_transcript_observable`). MS-3b’s **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`** are no longer the literal **`true`** hooks (see **`ms/TrueClause.ec`**).
- `DOMAIN_MS` is fixed to match `truth-engine/qssm-utils/src/hashing.rs` (not invented).
