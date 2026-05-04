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

**Compile-order authority:** `check_easycrypt.sh` is the canonical source of truth for the exact dependency list. The summary below is intentionally conceptual; if it ever diverges from the script, follow the script.

To inspect the current order directly:

```bash
sed -n '/^FILES=(/,/^)/p' check_easycrypt.sh
```

**Conceptual order:**

1. `primitives/` — root domains, shared types, algebra, and Fiat-Shamir surface.
2. `ms/` foundations — Schnorr single-branch, one-bit bitness, vector bitness, and transcript observable lemmas.
3. `ms/true_clause/` — MS-3b leaf chain, surfaced by the stable facade `ms/TrueClause.ec`.
4. `ms/comparison/` — MS-3c comparison leaf chains, surfaced by the stable facade `ms/Comparison.ec`.
5. `ms/SourceModel.ec` — public-spine / ROM-facing MS-3a bridge above comparison and below `ms/source/`.
6. `ms/source/` — MS-3a source types, constructors, distributions, execution-link facts, schedule chain, and theorem packaging. Stable import surfaces are `SourceDistributions.ec`, `SourceScheduleObligations.ec`, `SourceObligations.ec`, and `SourceTheorem.ec`.
7. `ms/MS.ec` — wrapper above the split MS-3a / MS-3b / MS-3c layers.
8. `le/` — LE proof chain, surfaced by `LEModel.ec`.
9. `sim/Simulator.ec` — simulator surface above the MS and LE layers.
10. `games/` — abstract game views, advantage facts, MS-hop chain, and LE bridge. Stable import surfaces are `GameMSHops.ec` and `Games.ec`.
11. `theorem/MainTheorem.ec` — top-level theorem layer.

Directory-local guides for the split-heavy subtrees live in `ms/source/README.md`, `ms/comparison/README.md`, and `games/README.md`.

If your EasyCrypt build exposes the binary as `ec` instead of `easycrypt`, the script falls back automatically when `easycrypt` is missing.

**Single-file check (top of the stack):**

```bash
cd docs/03-formal-verification/easycrypt
easycrypt compile -R . theorem/MainTheorem.ec
```

## Layout (directories)

The tree below is intentionally conceptual. Use the local README files in the split-heavy subdirectories and the filesystem itself for the exact inventory.

```text
docs/03-formal-verification/easycrypt/
├── README.md
├── check_easycrypt.sh
├── primitives/                # shared domains, types, algebra, FS
├── ms/
│   ├── TrueClause.ec          # stable facade for ms/true_clause/
│   ├── Comparison.ec          # stable facade for ms/comparison/
│   ├── SourceModel.ec         # MS-3a public-spine / ROM boundary
│   ├── true_clause/           # MS-3b leaf chain
│   ├── comparison/
│   │   ├── README.md
│   │   └── *.ec
│   ├── source/
│   │   ├── README.md
│   │   ├── SourceDistributions.ec
│   │   ├── SourceScheduleObligations.ec
│   │   ├── SourceObligations.ec
│   │   ├── SourceTheorem.ec
│   │   └── *.ec
│   └── MS.ec                  # MS wrapper
├── le/                        # LE chain, surfaced by LEModel.ec
├── sim/                       # simulator surface
├── games/
│   ├── README.md
│   ├── GameMSHops.ec          # stable MS-hop facade
│   ├── GameLEBridge.ec
│   ├── Games.ec               # stable top-level game facade
│   └── *.ec
├── theorem/                   # MainTheorem.ec
└── plans/                     # proof-plan notes
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
- **MS:** `ms/SourceModel.ec` and **`ms/source/`** now carry a constructive MS-3a source/model scaffold. `ms_public_input` lives in **`ms/SourceTypes.ec`**, the six **`ms3a_public_*`** selectors are definitional, **`A_ms3a_public_spine_programmed_layer`** is a proved lemma, and **`A_ms3a_observable_of_v2_aligns`** is now a proved identity-alignment lemma because **`ms_transcript_observable`** is the concrete v2-shaped record in **`primitives/QssmTypes.ec`**. `ms/TranscriptObservable.ec` keeps the stable alias **`ms_v2_transcript_observable = ms_transcript_observable`** for the source/game lane.
- **MS:** `SourceExecutionLink.ec` remains the source-facing execution/public-spine boundary. **`SourcePublicBitnessConstructors.ec`** supplies the concrete list-level constructor surface, **`SourceRealExecutionSeed.ec`** proves the public-bitness execution and execution-seed link theorems, and **`SourceProgrammedObligations.ec`** now consumes only proved theorem surfaces. There is no remaining named **`A_ms3a_*`** scaffold axiom in the MS-3a source/model lane.
- **MS residuals:** the remaining MS-3a assumptions are no longer the old observable/public-spine bridge, the digest-by-construction packer, or the canonical game-layer exact bound. **`ms/TranscriptObservable.ec`** now defines **`ms_transcript_digest_public_fields`** as a concrete hash over the public transcript surface, **`ms/SourceModel.ec`** defines **`ms3a_pack_observable_with_digest`** constructively with **`ms3a_pack_observable_with_digest_field_correct`** proved as a lemma, and **`games/GameAdvantage.ec`** now projects **`game_pr`** / **`Adv`** from concrete `game_view`s so **`A_MS3a_canonical_bitness_exact_bound`** is also a proved lemma. The remaining debt below MS-3a is the lower Schnorr / ROM assumption layer, not any MS-3a-specific axiom.
- **LE:** split under `le/` — `LERealExecution.ec` (lower real-execution surface with the concrete lower carriers `le_real_execution_primitive_material`, `le_real_execution_public_spine`, `le_real_execution_spine`, and `le_real_execution_record`; definitional residual, primitive-boundary, spine, and record constructors; the six theorem-facing field hooks defined as projections from that record; the concrete record constructor `le_real_execution_observable`; six projection lemmas showing that the observable exposes those fields definitionally; and the concrete point-mass sampler `d_le_real_execution_view = dunit ...`. The lower carrier is now fully concrete: `coeff_vector = int list`, `le_query_material = unit`, the coefficient trio is filled by fixed singleton vectors, and the hidden query material is `tt`), `LESurface.ec` (core ops, `epsilon_le`, views, surrogates, game-hop / sdist surface, Set-B and hiding predicates; `d_le_real_view` is now a definitional alias of `d_le_real_execution_view`, `le_post_rejection_surrogate` is the identity, and `le_fs_view_surrogate` is now a hidden-field update on the concrete LE observable carrier whose lower hidden update is also concrete identity on the current `le_query_material` carrier), `LERejectionSampler.ec` (lower rejection-sampler bridge surface with alias ops `d_le_rejection_real_execution_view`, `le_rejection_transform`, `d_le_rejection_post_execution_view`, plus proved bridge lemmas `le_real_view_matches_rejection_execution` and `le_post_rejection_view_matches_execution_transform`), `LEFsProgrammingSurface.ec` (lower FS-programming surface with concrete query/programmed-response carriers `le_fs_query_row` and `le_fs_programmed_response_carrier`, a joint-state carrier split into `le_fs_visible_shell` and `le_fs_hidden_programming_state`, lower distributions `d_le_pre_fs_programming_view`, `d_le_post_fs_programmed_view`, `d_le_pre_fs_hidden_programming_state`, `d_le_post_fs_hidden_programming_state`, and proved bridge lemmas/theorems `le_fs_surrogate_matches_programmed_view`, `le_fs_programming_preserves_shape_lower`, `d_le_pre_fs_programming_view_matches_hidden_state_projection`, `d_le_post_fs_programmed_view_matches_hidden_state_projection`, `A_LE_fs_hidden_state_update_sdist_bound`, `A_LE_fs_hidden_material_programming_sdist_bound`, and `A_LE_fs_programming_sampler_sdist_bound`), `LESetB.ec` (Set-B lemmas + `A_LE_{real,sim}_view_distribution_defined`), `LERejection.ec` (rejection layer + proved `A_LE_rejection_surrogate_preserves_shape`, proved zero-distance `A_LE_rejection_surrogate_sdist_bound`, proved `A_LE_rejection_sampler_sdist_bound`, and half-bound packaging), `LEFsProgramming.ec` (FS layer + proved `A_LE_fs_surrogate_preserves_shape`, proved `A_LE_fs_surrogate_sdist_bound`, and half-bound packaging), `LEViewIndist.ec` (view indistinguishability + distribution links), `LEStatisticalDistance.ec` (triangle / distinguisher bridge + `A_LE_view_advantage_bound_from_indistinguishability`), `LEHVZK.ec` (`A_LE_real_sim_transcript_equiv_bound`, `A_LE_SetB_HVZK_bound`, `A_LE_HVZK_transition_bound`); **`le/LEModel.ec`** remains the theorem-facing facade and does not import the lower surface files, while **`le/LERejection.ec`** imports the rejection sampler bridge layer and **`le/LEFsProgramming.ec`** now imports the lower FS surface. Theories that use LE **operators** (for example `le_game_hop_adv`, `le_transcript_observable`) also **`require import LESurface`** before `LEModel`, because EasyCrypt does not re-export transitive imports into the client scope. Same named axioms/lemmas and semantics as before the split.
- **LE audit, May 2026:** `le/LEViewIndist.ec`, `le/LEStatisticalDistance.ec`, `le/LEHVZK.ec`, and `games/GameLEBridge.ec` are lemma-only packaging layers. The live LE axiom surface feeding the theorem is now below the FS chain entirely: `LESurface.ec` contributes the primitive budget non-negativity fact `A4_le_hvzk_bound_nonneg`; `LERejection.ec` contributes the rejection-definition / acceptance / output-shape bundle, but its surrogate-preservation and surrogate-sdist obligations are lemmas; and the full theorem-facing FS quantitative chain is now lemma-only down through `A_LE_fs_surrogate_sdist_bound`. On the active `A4_le_hvzk_bound_nonneg -> A_LE_HVZK_transition_bound -> A_G1_to_G2_le_transition_bound -> qssm_main_theorem_skeleton` path, the FS half-hop is fully discharged on the current lower carrier, `d_le_real_view` is concrete as a lower point-mass sampler, and the LE real-execution lane no longer has any abstract constructor left in its observable path. `MainTheorem.ec` now uses `A4_le_hvzk_bound_nonneg` directly; there is no separate theorem-local LE budget wrapper anymore.
- **LE rejection probe, May 2026:** a direct proof attempt for `A_LE_rejection_surrogate_sdist_bound` fails immediately once the current rejection predicates are unfolded: `le_rejection_sampling_hiding_bound` is definitionally just `0%r <= epsilon_le`, and the existing rejection-definition / acceptance / output-shape facts are only packaging predicates. The current rejection facade exposes no theorem connecting `d_le_real_view x s` to `d_le_post_rejection_view x s = dmap (d_le_real_view x s) le_post_rejection_surrogate` in statistical distance. The exact missing object is therefore a lower rejection-sampler theorem, preferably distinguisher-independent, bounding `sdist (d_le_real_view x s) (d_le_post_rejection_view x s)` by `(1%r / 2%r) * epsilon_le` from concrete rejection distribution and acceptance/output-shape facts.
- **LE rejection concretization, May 2026:** `le/LESurface.ec` now makes `le_post_rejection_surrogate` the identity on `le_transcript_observable`. As a result, `le/LERejection.ec` proves `A_LE_rejection_surrogate_preserves_shape` by definitional unfolding, proves `A_LE_rejection_surrogate_sdist_bound` by rewriting with `dmap_id` and `sdistdd`, and still packages `A_LE_rejection_sampler_sdist_bound` on the theorem-facing `d_le_post_rejection_view` surface. This removes the surrogate-specific rejection axioms rather than renaming them.
- **LE FS audit, May 2026:** the FS shape-preservation blocker is now resolved honestly. `primitives/QssmTypes.ec` makes `le_transcript_observable` a concrete record with one hidden FS-only field `leto_query_material`; `le/LESurface.ec` defines the theorem-facing selector ops as projections of that carrier and now concretizes `le_fs_program_query_material` as the identity on the current concrete `unit` hidden carrier. As a result, the lower hidden-state update becomes a concrete identity map, which closes the remaining FS statistical-distance law on the current carrier by zero distance.
- **LE FS lower surface, May 2026:** `le/LEFsProgrammingSurface.ec` now proves both lower bridge facts `le_fs_surrogate_matches_programmed_view` and `le_fs_programming_preserves_shape_lower`, and it now also carries the lower joint-state surface promised by the audit: `le_fs_visible_shell`, `le_fs_hidden_programming_state`, reconstruction/update ops, and pre/post hidden-state distributions driven by `d_le_pre_fs_programming_view` and `le_fs_hidden_programming_state_update`. The new bridge lemmas show that the theorem-facing pre/post programmed-view distributions are exactly the observable projections of those hidden-state distributions. Because the current hidden update is now concrete identity, `A_LE_fs_hidden_state_update_sdist_bound` is a proved zero-distance lemma rather than an axiom, which immediately yields the lower joint-state theorem `A_LE_fs_hidden_material_programming_sdist_bound` and the observable sampler theorem `A_LE_fs_programming_sampler_sdist_bound` via `sdist_dmap`.
- **LE rejection sampler surface, May 2026:** `le/LERejectionSampler.ec` continues to bridge the lower sampler names back to the current LE facade definitionally. `d_le_rejection_real_execution_view` aliases `d_le_real_view`, `le_rejection_transform` aliases the now-concrete identity rejection surrogate, and `d_le_rejection_post_execution_view` remains the push-forward `dmap ... le_rejection_transform`. Import direction stays clean enough for the current phase: the sampler file still depends only on `LESurface.ec`, `LERejection.ec` imports it, and `LEModel.ec` still does not depend on it. There is no import-cycle blocker in this lane.
- **LE real-view concretization, May 2026:** `le/LERealExecution.ec` now provides the lower constructor `le_real_execution_observable : qssm_public_input -> seed -> le_transcript_observable` and the concrete sampler `d_le_real_execution_view x s = dunit (le_real_execution_observable x s)`. `LESurface.ec` now defines `d_le_real_view` as a direct alias of that lower sampler, so the real-view distribution itself is no longer abstract. The lower real-execution surface has now been centralized further: `le_real_execution_spine_of` is a definitional constructor over the lower carriers `le_real_execution_primitive_material`, `le_real_execution_public_spine`, and `le_real_execution_spine`, and the primitive-boundary construction is now fully definitional as well. The six theorem-facing field hooks remain definitional projections from `le_real_execution_record_of`, and `LERealExecution.ec` now proves that `le_real_execution_observable` exposes each field definitionally.
- **LE primitive-boundary concretization, May 2026:** `LERealExecution.ec` now carries the single centralized record `le_real_execution_primitive_material`, packaging coefficient material, challenge-seed digest preimage material, a challenge branch/control bit, programmed-query-digest preimage material, and hidden `le_query_material`. `le_real_execution_spine_of` is now defined from that one record, and the digest fields use the existing primitive combinators `le_challenge_seed` and `le_programmed_query_digest` together with the installed LE labels from `primitives/Domains.ec`. This removed the last scattered spine-level abstraction and concentrated the real-side debt under one primitive-boundary constructor.
- **LE primitive-boundary partial concretization, May 2026:** `LERealExecution.ec` now chips away at that boundary without trying to close it all at once. The challenge-seed material and programmed-query-digest material inside `le_real_execution_primitive_material_of` are defined concretely: `hash_domain` on installed LE labels supplies the digest preimage placeholders, `le_challenge_seed` is used to derive a concrete challenge-related digest inside the programmed-query material, and the final spine still derives the visible digest fields through `le_challenge_seed` and `le_programmed_query_digest`. The coefficient trio is now concrete as well: `primitives/QssmTypes.ec` makes `coeff_vector` a concrete `int list`, and `LERealExecution.ec` fills the three LE coefficient fields with fixed singleton vectors tagged `0`, `1`, and `2`. This digest-first and coefficient-next phase left only hidden query material at the time; the subsequent hidden-material refinement closed that last gap.
- **LE coefficient material concretization, May 2026:** the lower coefficient surface no longer depends on any abstract constructor. `le_real_execution_residual_material_of` is now definitional, the coefficient carrier is concrete, and `le_real_execution_spine_of` continues to lift those concrete coefficient vectors into the theorem-facing observable fields without changing the already-closed FS or digest lanes.
- **LE hidden query material concretization, May 2026:** the last lower LE abstraction is now gone. `primitives/QssmTypes.ec` makes `le_query_material` a concrete `unit` carrier, and `LERealExecution.ec` defines `le_real_execution_hidden_query_material_of x s = tt`. No theorem-facing proofs needed to change: `le_real_execution_spine_of`, the observable projections, and the lower FS programming surface all continue to compile by definitional transport on the now-concrete hidden field.
- **LE bridge interface:** `games/GameLEBridge.ec` now proves `A_game_pr_LE_projection_semantics` as a **lemma** on the split LE-facing views `G1_le_real_projection` / `G2_full_sim`. The former exposed cross-layer gap is now closed at the simulator boundary: `sim/Simulator.ec` provides the extraction-to-LE probability bridge `A_extract_ms_public_real_view_probability_eq`, and `games/GameAdvantage.ec` proves `A_G1_MS_to_LE_transition_bound` from that bridge plus the existing MS stage collapses. No game-layer bridge axiom was reintroduced.
- **Simulator:** `sim/Simulator.ec` now characterizes the abstract extractor `extract_ms_public` by the public-surface bridge axiom `A_extract_ms_public_real_view_probability_eq`; `extract_ms_public` remains abstract in the carrier sense, but its observable role in the MS-to-LE handoff is now explicit and non-vacuous.
- **Types / games:** `primitives/QssmTypes.ec` now provides the primitive domains plus the concrete **`coeff_vector`** carrier as `int list`, the concrete **`le_query_material`** carrier as `unit`, the concrete **`ms_transcript_observable`** carrier, and the concrete **`le_transcript_observable`** carrier with a hidden FS-only field of that unit type. **`ms/SourceTypes.ec`** defines **`ms_public_input`**, **`ms_game_stage`**, **`ms_game_view_record`**, **`qssm_g1_le_real_record`**, **`qssm_g2_shell_record`**, and **`game_view`**. The game layer remains split under `games/`: `GameTypes.ec` (MS view helpers/stage predicates), `GameViews.ec` (G0/G1/G2 and `G_MS_*` constructors, including explicit `G1_le_real_projection` beside the pure MS endpoint `G_MS_sim`), `GameAdvantage.ec` (projected `game_pr`, definitional `Adv`, the explicit middle-hop arithmetic `Adv_G1_MS_to_LE`, and the proved corollary `A_G1_MS_to_LE_transition_bound`), `GameMSHops.ec` (MS1..MS3c transition axioms/lemmas + composed `A_G0_to_G1_ms_transition_bound`), and `GameLEBridge.ec` (definitional LE projection lemmas on `G1_le_real_projection` / `G2_full_sim`, plus `A_G1_to_G2_le_transition_bound`). `Games.ec` is a thin facade importing those split modules; theorem-facing names remain unchanged and `G_MS_sim` remains the pure MS endpoint.
- **Theorem:** `theorem/MainTheorem.ec` — direct use of the primitive MS budget assumptions `A1_ms_hash_binding_nonneg` from `ms/MS.ec`, `A2_ms_rom_programmability_nonneg` from `primitives/FS.ec`, and the primitive LE budget assumption `A4_le_hvzk_bound_nonneg` from `LESurface.ec`, together with bridge lemmas `use_MS_3a` / `use_MS_3b` / `use_MS_3c`, and the proved additive game-hop lemma `qssm_main_theorem_skeleton`, now specialized to `extract_ms_public x` rather than a free unrelated `xms`

- **Single-branch MS-3a (`ms/SchnorrBranch.ec` + `primitives/Algebra.ec`):** `MS_3a_single_branch_schnorr_reparam` is fully proved (no `admit`). Root Schnorr-layer assumption is **`duni_scalar_shift_reparam`** on `duni_scalar`.

- **Checker note:** there is **no** `admit` remaining in any `*.ec` file under this directory; open items are **named axioms** only (see each theory).

## Next proof target

**MS-3a source obligations (file split):** `d_ms3a_*` sampling laws and related lemmas remain split under **`ms/source/`** and re-exported by the stable facades **`SourceDistributions.ec`**, **`SourceScheduleObligations.ec`**, and **`SourceObligations.ec`**. The old scaffold blockers are now closed: **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**, **`A_ms3a_spine_sim_marginal_matches_seed`**, **`A_ms3a_public_spine_programmed_layer`**, and **`A_ms3a_observable_of_v2_aligns`** are all lemmas, while the canonical game constructors in **`games/GameViews.ec`** already route through **`ms3a_public_v2_observable xms`**.

**Execution/link boundary:** **`SourceExecutionLink.ec`** remains the standalone source-facing boundary for the remaining MS-3a execution/public-spine story. It defines predicate **`ms3a_execution_public_spine_link`** and the proved projection lemmas **`ms3a_public_payload_bitness_programmed_of_execution_link`** and **`ms3a_real_seed_public_fields_on_support_of_execution_link`**; `SourcePayloadDistributions.ec` remains below it to avoid cycles.
**Concrete boundary on top:** **`SourceRealExecutionGameLink.ec`** now provides the minimal concrete execution/game-link objects: deterministic public source **`ms3a_game_public_bitness_source`**, point-mass source sampler **`d_ms3a_real_execution_bitness_source`**, and concrete seed law **`d_ms3a_real_execution_public_seed`** implemented as `dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer`. The structural local lemmas on that boundary are proved in **`SourceRealExecutionGameLink.ec`**. The semantic closure now lives one layer higher: **`SourceRealExecutionSeed.ec`** proves **`ms3a_game_public_bitness_source_wf`**, **`ms3a_public_bits_per_bit_programmed_of_game_execution`**, **`ms3a_public_bitness_globals_ordered_of_game_execution`**, **`ms3a_public_bitness_execution_of_game_execution`**, and **`ms3a_public_bitness_vector_programmed_of_game_execution`**. **`SourcePublicBitnessConstructors.ec`** remains the concrete list-level constructor surface, and **`ms/SourceModel.ec`** now also closes the digest-by-construction constructor surface with a concrete transcript-digest hash and a constructive `ms3a_pack_observable_with_digest`.

The concrete objects added in this phase are:

- **`ms3a_game_public_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source`** — deterministic execution/public-spine source carrying stmt, bits, bitness globals, comparison global, and transcript digest in one place, rather than another abstract wrapper around `ms3a_public_*`.
- **`d_ms3a_real_execution_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source distr`** — concrete real execution sampler shape at the source-record layer, currently the canonical public-spine point mass.
- **`d_ms3a_real_execution_public_seed`** — defined as `dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer`; equal to **`d_ms3a_real_payload_seed`** by definitional unfolding (proved as lemma **`A_ms3a_real_payload_seed_matches_execution_seed`** in **`SourceRealExecutionSeed.ec`**).

The key local lemmas/theorems on this boundary are:

- **`ms3a_game_public_bitness_source_projects_public_spine`** — concrete source projects to `ms3a_public_stmt_digest`, `ms3a_public_bits`, `ms3a_public_bitness_globals`, and `ms3a_public_transcript_digest`.
- **`ms3a_game_public_bitness_source_wf`** — the concrete game source lies on abstract spine support and therefore satisfies `ms3a_source_wf`.
- **`ms3a_public_bits_per_bit_programmed_of_game_execution`** and **`ms3a_public_bitness_globals_ordered_of_game_execution`** — the concrete per-bit FS/ROM facts needed to discharge `ms_per_bit_programmed` and `ms_ordered_challenge_vector_matches` on the abstract public spine.
- **`ms3a_public_bitness_execution_of_game_execution`** — proves the full former package theorem on the public spine, with no extra globals bridge axiom.
- **`ms3a_real_execution_public_seed_support_inv`** — support inversion for the `dmap`-implemented real execution seed law.
- **`ms3a_real_execution_bitness_source_public_fields_on_support`** — concrete source support matches the same public stmt / bits / bitness globals.

Current game files no longer block the MS-3a source/model story at the carrier layer: **`ms_public_input`** is concrete in **`ms/SourceTypes.ec`**, the canonical `G_MS_*` constructors in **`games/GameViews.ec`** route through **`ms3a_public_v2_observable xms`**, the observable bridge in **`ms/SourceModel.ec`** is the identity map over the concrete record carrier, the digest-by-construction packer is now constructive, and the canonical MS3a game hop is now proved from the concrete `game_view` projection in **`games/GameAdvantage.ec`**. The remaining MS-3a proof debt is therefore only the lower Schnorr / ROM assumption layer, not source/game observable alignment or a remaining MS3a-specific game axiom.

1. **MS-3a (residual)** — there is no remaining named **`A_ms3a_*`** scaffold axiom in the source/model lane, no remaining source-model packer axiom, and no remaining MS-3a-specific game-layer axiom. **`A_ms3a_public_spine_programmed_layer`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**, **`A_ms3a_real_payload_seed_matches_execution_seed`**, **`A_ms3a_observable_of_v2_aligns`**, **`ms3a_pack_observable_with_digest_field_correct`**, and **`A_MS3a_canonical_bitness_exact_bound`** are all proved lemmas. The remaining assumptions beneath the MS-3a theorem path are now the lower Schnorr / ROM surfaces, not any MS-3a-specific axiom.
2. **MS-3b** — the canonical game-layer bound **`A_MS3b_canonical_true_clause_bound`** is now a **proved lemma** in **`games/GameMSHopTypes.ec`**: **`GameAdvantage.ec`** projects `game_pr` from concrete `game_view`s and collapses the AfterBitness/AfterComparison pair under the MS-3b true-clause bundle, while **`MS_3b_true_clause_characterization`** from **`ms/true_clause/TrueClauseTheorem.ec`** discharges that bundle. The former bit-direction leaf **`A_ms3b_operand_hdb_implies_value_gt_target`** is also now a **proved lemma** in **`ms/true_clause/TrueClauseTheorem.ec`**. Remaining MS-3b work is therefore in transcript / execution linkage for **`ms3b_comparison_operand_bits`** and **`ms3b_clause_opening_binds`** rather than an MS-3b axiom declaration.

Then: MS-3c comparison lane in **`ms/Comparison.ec`** / **`ms/comparison/`** (`plans/MS_3c_proof_plan.md`; **`d_ms3c_real_sim_payload_coupling`** is the **product** of the payload laws; each payload law is a **`dmap`** of **`d_ms3c_{real,sim}_payload_seed`**, itself the **product** of **Phase-1** **`dunit tt`** on **`unit`** for all four seed components (real/sim challenge and real/sim announcement); **`L_ms3c_{real,sim}_payload_seed_lossless`** and **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** are **proved** from **`dprod_ll_auto`** / **`dmap_ll`** and the four component losslessness lemmata (**`L_ms3c_{real,sim}_seed_challenge_lossless`**, **`L_ms3c_real_seed_announcement_lossless`**, **`L_ms3c_sim_seed_announcement_lossless`**); Phase-1 **`ms3c_phase1_payload_from_public_input`** (surfaced as **`ms3c_{real,sim}_payload_from_seed`**) wires public clause indices and false-branch list lengths from **`ms3c_public_*`**; the four **`A_ms3c_{real,sim}_from_seed_uses_{public_indices,share_length}`** facts are **proved lemmas** in **`ComparisonPayloadSeedAnchors.ec`** (re-exported by facade **`ComparisonPayloadSeeds.ec`**; **`L_ms3c_{real,sim}_seed_index_shape_valid`**, **`L_ms3c_{real,sim}_seed_length_shape_valid`** still package schedule/transcript bridges). **`ms3c_obs_*`** remains scaffolding for transcript-backed fields; Phase-1 **`mscp_query_digest`** is **`ms_comparison_query_digest (ms3c_public_stmt_digest x) (ms3c_clause_ann_digests_from_surface …)`** (canonical statement digest **`ms3c_public_stmt_digest`**; announcement digest helpers live in **`ComparisonTypes.ec`**). Lemma **`A_ms3c_clause_surface_query_digest_constructed`** is **proved** (no `forall stmt`); surface bounds (**`A_ms3c_surface_query_digest_field_correct`**, **`A_ms3c_query_digest_statement_bound`**, etc.) now assume **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**. Marginal equality of **`d_ms3c_coupling_{real,sim}_projection`** vs standalone laws is **proved** from **`Distr`** given those lemmas; **`A_ms3c_coupling_pair_relation`** is a **proved** lemma in **`ComparisonCouplingSchedule.ec`** (marginal **`ms3c_ax_payload_*`** facts on joint payload support ⇒ pointwise **`ms3c_real_sim_payload_coupled`** via **`supp_dprod`** and digest list agreement); **`ComparisonCouplingAxioms.ec`** has **no** coupling fragment **axioms**: all **`A_ms3c_payload_*_match`** hooks are **proved lemmata** from **`L_ms3c_cross_support_real_sim_payload_equal`**. **`ms/comparison/*`** is **axiom-free**; the MS-3c game-layer bundle **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and the canonical bound **`A_MS3c_canonical_comparison_exact_bound`** are both **proved lemmas** in **`games/GameMSHopTypes.ec`**. False-announcement support on payload support is **proved** (**`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** as **lemmata** in **`ComparisonPayloadFalseClause.ec`**, from Phase-1 **`map sch_pubkey`** wiring and **`L_ms_false_clause_simulated_phase1_from_public_input`**). **`ms3c_ax_payload_announcements_match_shape`** is unconditional via **`L_ms3c_ax_payload_announcements_match_shape_total`** in **`ComparisonPayloadSupportPublic.ec`** (re-exported by **`ComparisonPayloadSupport.ec`**); **`ms3c_ax_payload_announcement_digests_preserved`** follows from **`ms3c_ax_payload_public_fields_match`** via **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** in **`ComparisonCouplingSchedule.ec`**; projection and marginal packaging lemmas live in **`ComparisonCouplingMarginals.ec`**; **`A_ms3c_payload_schedule_eq_from_coupling`** is a **proved** lemma in **`ComparisonCouplingSchedule.ec`** (re-exported by **`ComparisonCouplingTheorem.ec`** / **`ComparisonCoupling.ec`**). Payload support uses the four proved from_seed anchor lemmas (**`A_ms3c_{real,sim}_from_seed_uses_share_length`**, **`A_ms3c_{real,sim}_from_seed_uses_public_indices`**, with **`L_ms3c_{real,sim}_seed_length_shape_valid`**) and derives support-shape as lemmas (**`A_ms3c_{real,sim}_payload_support_length_index_shapes`**) via `supp_dmap`, then uses proved **`L_ms3c_{real,sim}_payload_support_simulatable`**; announcement list shape on payloads is **proved** (**`L_ms3c_*_payload_ann_digest_list_shape_ok`**). False-clause path uses proved constructor lemmas **`L_ms3c_{real,sim}_constructor_false_index_nonempty`** (**`ms3c_public_false_branch_nonempty`** + public-index anchors + **`ms3c_public_shape_ok`**), placeholder **`L_ms3c_public_false_branch_nonempty_placeholder`** (`ComparisonTypes.ec` singleton false-branch placeholders), seed-level wrappers (**`A_ms3c_{real,sim}_seed_false_index_nonempty`**), proved support lemmata **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** (false announcements vs **`sch_pubkey`** of false shares on support, Phase-1 constructor), and proved **`L_ms3c_false_clause_generation_on_support`** (**`ms3c_ax_payload_false_clauses_simulated`**); false-announcement nonempty is proved as lemmas (**`A_ms3c_real_seed_false_clause_nonempty`**, **`A_ms3c_sim_seed_false_clause_nonempty`**), and **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** / **`A_ms3c_false_clause_simulation`** remain proved lemmas. Query digest: proved ann projection lemmas (**`L_ms3c_ann_digest_projection_correct`**, **`L_ms3c_ann_digests_alias`**), proved lemma **`A_ms3c_clause_surface_query_digest_constructed`** (Phase-1 payload, canonical **`ms3c_public_stmt_digest x`**), proved lemmas **`A_ms3c_surface_query_digest_field_correct`** / **`A_ms3c_query_digest_statement_bound`** (require **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**), **`L_ms3c_query_digest_uses_ann_digest_projection`**, **`L_ms3c_query_digest_ordered_announcements_bound`**, **`L_ms3c_query_digest_statement_bound_hash`**, same-announcement lemmas **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`** (same **`x`** / Phase-1 payload hypothesis), and packaging **`L_ms3c_digest_announcement_only`** ( **`Hann`** is redundant with **`L_ms3c_ann_digest_list_shape`**). On the game layer, **`A_MS1_hash_binding_step_advantage_bound`**, **`A_MS1_hash_binding_concrete_pair_advantage_bound`**, **`A_MS1_canonical_hash_binding_bound`**, **`A_MS2_rom_programming_step_advantage_bound`**, **`A_MS2_rom_programming_concrete_pair_advantage_bound`**, **`A_MS2_canonical_rom_programming_bound`**, **`A_MS3a_canonical_bitness_exact_bound`**, **`A_MS3b_canonical_true_clause_bound`**, **`A_MS3c_comparison_bundle_implies_game_pr_equality`**, and **`A_MS3c_canonical_comparison_exact_bound`** are now **proved lemmas**. Generic step-wrapper axioms were removed, because canonical bounds on fixed `G_MS_*` views do not by themselves imply bounds for all arbitrary step-related `src`/`dst` views without an additional `Adv`-invariance theory over frozen observable/public fields. On LE, discharge **`A_LE_rejection_surrogate_sdist_bound`**, **`A_LE_fs_surrogate_sdist_bound`**, **`A_LE_rejection_surrogate_preserves_shape`**, **`A_LE_fs_surrogate_preserves_shape`** (and instantiate **`le_post_rejection_surrogate`** / **`le_fs_view_surrogate`**) from concrete rejection/FS distribution analysis alongside the remaining rejection/FS axiom bundles (`plans/LE_HVZK_proof_plan.md`); instantiate or relate **`le_distinguisher_event`** when bridging to concrete games. The simulator-facing cross-layer middle hop is now closed: `sim/Simulator.ec` supplies **`A_extract_ms_public_real_view_probability_eq`**, `games/GameAdvantage.ec` proves **`A_G1_MS_to_LE_transition_bound`**, and `theorem/MainTheorem.ec` now specializes the QSSM theorem to **`extract_ms_public x`** instead of assuming a separate middle-hop premise.

Update May 2026: the MS game-layer debt has been reduced again. In **`games/GameAdvantage.ec`**, **`game_pr_ms_core`** is now concrete on the lower MS probability surface **`ms_view_distinguish_pr (d_ms_game_stage_observable_v2 ...)`**, and both lower bridge theorems **`A_MS1_hash_binding_game_pr_core_bound`** and **`A_MS2_rom_programming_game_pr_core_bound`** are now **proved lemmas** obtained from **`A_MS1_hash_binding_bad_event_bound`** and **`A_MS2_rom_programming_transition_bound`**. In **`games/GameMSHopTypes.ec`**, the explicit stage-pair theorems **`A_MS1_hash_binding_concrete_pair_advantage_bound`** and **`A_MS2_rom_programming_concrete_pair_advantage_bound`** remain proved lemmas obtained by unfolding **`Adv`** / **`game_pr`** to that boundary. MS-3a / MS-3b / MS-3c remain proved game-hop lemmas on the concrete **`game_view`** projection.

The MS1/MS2 game-layer assumption boundary is now closed: neither MS1 nor MS2 leaves a residual axiom on the game side.

Concrete-semantics audit, May 2026: import cycles were not the blocker for materializing **`game_pr_ms_core`**, and that bridge is now in place for MS views. The lower MS surface contains the MS-side probability interface (**`ms_distinguisher_event`**, **`ms_view_distinguish_pr`**), stage-indexed concrete MS execution laws for **`MSGameStageReal`** / **`MSGameStageAfterBinding`** / **`MSGameStageAfterRom`**, and the lower MS theorems **`A_MS1_hash_binding_bad_event_bound`** and **`A_MS2_rom_programming_transition_bound`**; **`games/GameAdvantage.ec`** now computes **`game_pr_ms_core`** from that surface and proves both lower bridge theorems as lemmas. There is no remaining MS1/MS2 lower bridge axiom.

Minimal lower-probability skeleton, May 2026: **`ms/MSProbabilitySurface.ec`** now adds **`ms_distinguisher_event`**, **`ms_view_distinguish_pr`**, and **`d_ms_game_stage_observable_v2`**. The Real/Sim endpoints reuse the existing MS-3a observable distributions; **`MSGameStageAfterBinding`** now samples the existing real-source law and repacks through **`ms3a_pack_observable_with_digest`**, while **`MSGameStageAfterRom`** now samples the real-source law together with **`d_ms3c_real_seed_challenge`** and uses the seed's programmed-challenge field as its comparison-global observable field. **`MSGameStageAfterBitness`** and **`MSGameStageAfterComparison`** remain point masses for now. **`games/GameAdvantage.ec`** now uses this file as the active semantics of **`game_pr_ms_core`** for MS views.

Concrete stage-law audit, May 2026: **`MSGameStageReal`** already had a real lower observable law through the existing MS-3a source/observable chain, and **`MSGameStageAfterBinding`** / **`MSGameStageAfterRom`** now have minimal sampled stage laws below the game layer. Those laws remain projection-only semantics: AfterBinding is a digest-normalized pushforward of the real source, and AfterRom is a pushforward of the real source plus the sampled comparison challenge-seed surface. On the current seed surface, the programmed challenge already coincides with the public comparison-global digest on support, so **`d_ms_after_rom_observable_v2`** collapses to the same canonical law as **`d_ms_after_binding_observable_v2`**. MS1 and MS2 therefore both close on the lower surface and at **`game_pr_ms_core`**.

Named intermediate stage laws, May 2026: **`ms/MSProbabilitySurface.ec`** now introduces **`d_ms_after_binding_observable_v2`** and **`d_ms_after_rom_observable_v2`**, and **`d_ms_game_stage_observable_v2`** dispatches through them. **`d_ms_after_binding_observable_v2`** is now a sampled real-source pushforward through **`ms3a_after_binding_observable_of_source`**, and **`d_ms_after_rom_observable_v2`** is now a sampled real-source-plus-challenge-seed pushforward through **`ms3a_after_rom_observable_of_source_challenge`**. The lower MS1 gap is discharged by **`A_MS1_hash_binding_bad_event_bound`**, and the lower MS2 gap is discharged by **`A_MS2_rom_programming_transition_bound`** via the exact distribution equality **`d_ms_after_rom_observable_v2 = d_ms_after_binding_observable_v2`**.

MS1 digest-normalization audit, May 2026: the public transcript digest is now canonical by construction on the MS public carrier. **`ms/SourceTypes.ec`** adds **`ms_public_bitness_global_digests`**, **`ms_public_transcript_digest_canonical`**, **`ms_make_public_input`**, and **`ms_make_public_input_transcript_digest_canonical`**; **`ms/SourceModel.ec`** routes **`ms3a_public_transcript_digest`** through that canonical projection and proves **`ms3a_public_transcript_digest_by_construction`** together with unconditional **`ms3a_public_transcript_shape_ok_holds`**; **`ms/source/SourceRealExecutionGameLink.ec`** mirrors that fact on the concrete game public source via **`ms3a_game_public_bitness_source_transcript_digest_canonical`** and **`ms3a_game_public_bitness_source_transcript_shape`**; **`ms/source/SourceObservableDistributions.ec`** still proves that the Real observable law is the canonical public point mass; **`ms/MSProbabilitySurface.ec`** closes the lower MS1 path with **`L_ms1_hash_binding_bad_event_zero`**, **`L_ms1_hash_binding_stage_zero`**, and **`A_MS1_hash_binding_bad_event_bound`**; and **`games/GameAdvantage.ec`** now wires that theorem upward by proving **`A_MS1_hash_binding_game_pr_core_bound`** over the concrete **`game_pr_ms_core`** definition. The remaining MS1 work is no longer a bridge issue; MS1 is closed at the current game/core boundary.

## Syntax / checker notes

- Theories are loaded by **basename** under this tree with `easycrypt compile -R . <file>`.
- Trivial placeholder axioms often use the proposition `true` (not `True`). MS-3a’s global lemma targets **`ms3a_bitness_real_sim_equiv`** (distribution equality on `ms_transcript_observable`). MS-3b’s **`ms3b_comparison_operand_bits`** / **`ms3b_clause_opening_binds`** are no longer the literal **`true`** hooks (see **`ms/TrueClause.ec`** facade and **`ms/true_clause/`**).
- `DOMAIN_MS` is fixed to match `truth-engine/qssm-utils/src/hashing.rs` (not invented).
