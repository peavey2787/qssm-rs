# MS-3a Proof Plan (EasyCrypt)

This note is **design + formal target tracking** for MS-3a. **`MS_3a_exact_bitness_simulation` is not vacuous**: it proves the predicate **`ms3a_bitness_real_sim_equiv`** (equality of abstract `ms_transcript_observable` distributions) via the layered lemma **`MS_3a_exact_bitness_simulation_from_layers`**. The skeleton admit is now discharged via a named packaging bridge lemma; remaining open obligations are listed in the checklist.

**`ms/source/` obligations layout:** lemmas and axioms are split across **`SourceProgrammedObligations.ec`** (programmed-on-support seed layer), **`SourcePublicFieldObligations.ec`** (paired public fields and payload-support public bridges), and the schedule chain **`SourceScheduleSeed.ec`** / **`SourceSchedulePayload.ec`** / **`SourceScheduleTheorem.ec`** (re-exported by facade **`SourceScheduleObligations.ec`**). **`SourceObligations.ec`** re-exports them; **`require import SourceObligations`** is unchanged.

## Exact statement (theorem layer)

From `docs/02-protocol-specs/qssm-zk-theorem-spec.md`:

- **MS-3a**: exact bitness transcript simulation under programmed challenges.

Intended meaning (informal): once the bitness Fiat–Shamir query is programmed, every witness-using bitness branch is **distribution-identical** to a simulated Schnorr branch on the frozen observable boundary (zero residual advantage term).

## What is now formalized (single-branch core)

File: **`ms/SchnorrBranch.ec`** (after `primitives/QssmTypes.ec`; see `check_easycrypt.sh`).

### Observable distributions (equality target)

Both are values of type `schnorr_single_bit_obsv distr` (i.e. distributions over `sch_point * scalar`):

- **Real** `d_ms3a_schnorr_real w c`: draw `alpha <- duni_scalar`, output `(alpha * H, alpha + c * w)`.
- **Sim** `d_ms3a_schnorr_sim w c`: draw `z <- duni_scalar`, output `(z * H - c * (w * H), z)` with `w * H` written as `sch_pubkey w`.

**Lemma** `MS_3a_single_branch_schnorr_reparam`: `forall w c, d_ms3a_schnorr_real w c = d_ms3a_schnorr_sim w c` — **proved** (no `admit`) from:
- **`duni_scalar_shift_reparam`** (axiom: uniform shift on `duni_scalar` for the joint observable pair, with translation `t = c * w` instantiated as `sch_s_mul c w`), then
- **`in_eq_dlet`** to push pointwise equality of continuations, **`ms3a_schnorr_reparam_obs_eq`** (pair equality from `sch_sim_announcement_reparam` via **`qssm_pair_eq`**), and **`qssm_dunit_eq`** on the point mass.

### Proved algebraic / packaging lemmas (Schnorr file)

- `sch_neutralR`, `sch_add_pt_oppR`, `sch_pt_add_cancel`, `sch_smul_sub_gen`, `sch_sim_announcement_reparam` — see `primitives/Algebra.ec`.
- `qssm_pair_eq`, `qssm_dunit_eq`, `ms3a_schnorr_reparam_obs_eq` — structural (pair + `dunit` congruence).

## Axiom inventory in `ms/SchnorrBranch.ec` (classification)

| Name | Class | Role |
|------|-------|------|
| `sch_s_addA`, `sch_s_addC`, `sch_s_sub_def`, `sch_s_mul_add_distr` | **(A)** | Scalar fragment. |
| `sch_addA`, `sch_addC`, `sch_neutralL`, `sch_oppL` | **(A)** | Point group fragment. |
| `sch_smul_add_gen`, `sch_smul_mul_embed` | **(A)** | Homomorphism at `H`. |
| `duni_scalar` | **(B)** | Uniform scalar source. |
| `duni_scalar_invariant_add` | **(B)** | Translation invariance. |

### (D) Remaining root obligation (single-branch)

| Item | Notes |
|------|--------|
| `duni_scalar_shift_reparam` | **Axiom** — finite-field style uniform-shift reparameterization for joint pair `(alpha*H, alpha+t)` vs `((z-t)*H, z)`. |

## Fiat–Shamir / programmed challenge surface (`primitives/FS.ec`)

Execution-spec anchor: **`qssm-zk-concrete-execution-spec.md` section F** (Engine B v2 query/challenge path). Label strings live in `primitives/Domains.ec` (`LABEL_MS_V2_BITNESS_QUERY`, `LABEL_MS_V2_QUERY_SCALAR`); no new labels in EC.

| Name | Role |
|------|------|
| `ms_bitness_query_digest` | Abstract `hash_domain(DOMAIN_MS, [label, statement_digest, bit_index, announce_zero, announce_one])` at digest level. |
| `ms_query_to_scalar` | Abstract `hash_to_scalar(LABEL_MS_V2_QUERY_SCALAR, [query_digest])`. |
| `ms_bitness_fs_scalar stmt i d0 d1` | Composite `ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1)` — global FS scalar for one bitness query. |
| `ms_bitness_fs_programmed stmt i d0 d1 cglob` | Predicate `cglob = ms_bitness_fs_scalar stmt i d0 d1` (cglob **not** free once this holds). |
| `A2_bitness_programmed_challenge` | **Proved lemma**, exact instance of **`A2_programmable_oracle_exists`** at digest `ms_bitness_query_digest stmt i d0 d1` — **not** a new cryptographic axiom. |

## One-bit OR bitness model (`ms/BitnessOne.ec`)

**Location:** after `primitives/FS.ec`, before the MS-3a observable frame (`ms/SourceModel.ec`) and `ms/source/` theories. **Imports:** `QssmSchnorrSingleBit`, **`QssmFS`**.

### Transcript shape

Record **`ms_single_bit_or_transcript`**: statement digest `msbt_stmt`, public points `msbt_pub0` / `msbt_pub1`, branch observables `msbt_branch0` / `msbt_branch1`, challenges `msbt_challenge_zero` / `msbt_challenge_one`, global `msbt_global_challenge`.

**Split:** `ms_challenges_split c0 c1 cglob` ↔ `sch_s_add c0 c1 = cglob`.

**Programmed one-bit relation** `ms_single_bit_programmed_bitness_transcript stmt i P0 P1 o0 o1 c0 c1 cglob`: announcements match observables (`o0.`1, `o1.`1), split holds, and `ms_bitness_fs_programmed` on digests `ms_single_bit_branch_digest P0` / `P1` (abstract lane material for section F preimages).

### Joint distributions on `(branch0, branch1)`

- **`d_ms_bit_or_real_bitfalse` / `d_ms_bit_or_real_bittrue` / `d_ms_bit_or_sim_both`** — unchanged.
- **`d_ms_bit_or_pack`** — unchanged.

### OR-split lemmas (proved; use `MS_3a_single_branch_schnorr_reparam`)

| Lemma | Status |
|--------|--------|
| `MS_3a_single_bit_or_split_bit_zero` | **Proved** |
| `MS_3a_single_bit_or_split_bit_one` | **Proved** |
| `MS_3a_single_bit_or_split_exact_simulation` | **Proved** |

### Programmed-FS layer (one bit)

| Lemma | Status | Notes |
|--------|--------|--------|
| `MS_3a_single_bit_bitness_fs_consistent` | **Proved** | Characterizes `ms_bitness_fs_programmed` as equality with `ms_bitness_fs_scalar`. |
| `MS_3a_single_bit_programmed_or_split_exact_simulation` | **Proved** | Under FS programming + split, same conclusion as `MS_3a_single_bit_or_split_exact_simulation`; proof invokes `A2_bitness_programmed_challenge` then delegates to OR-split (OR proof does not yet consume ROM beyond bookkeeping). |

## Real / sim bitness transcript (full MS v2)

**Source packaging (`ms/source/SourceTypes.ec`, `SourceConstructors.ec`, `SourceDistributions.ec` facade over `SourcePayloadDistributions` / **`SourceCouplingTheorem`** / `SourceBitnessDistributions` / `SourceDistributionLemmas` / `SourceObservableDistributions`):** `ms3a_real_source_payload` / `ms3a_sim_source_payload` are record types whose fields match the arguments to `ms3a_make_real_source` / `ms3a_make_sim_source`. **Seed** types `ms3a_real_payload_seed` / `ms3a_sim_payload_seed` are **aliases** of those payload records (same field surface: stmt, result, bits, bitness global challenges, comparison global challenge, transcript digest). **`ms3a_real_payload_from_seed`** / **`ms3a_sim_payload_from_seed`** are the **identity** on that shared type (parameters `x` / `s` reserved for keyed sampling from execution). Laws **`d_ms3a_real_source_payload`** / **`d_ms3a_sim_source_payload`** are **by definition** `dmap` pushforwards of abstract **`d_ms3a_{real,sim}_payload_seed`** through those maps. Laws `d_ms3a_bitness_real_source` / `d_ms3a_bitness_sim_source` remain **by definition** `dmap` of payload laws through `ms3a_bitness_layer_source_of_{real,sim}_payload`.

**Rust/spec anchors:** `internals.rs`, execution spec F.

**Refined vs earlier plan:** `cglob` can be tied to `ms_bitness_fs_scalar` via `ms_bitness_fs_programmed`; digest wiring for announcements is still abstract (`ms_single_bit_branch_digest`).

## Assumptions needed (system level)

- **`A2_programmable_oracle_exists`** (`primitives/FS.ec`) — ROM / programming surface.
- No leakage beyond observable boundary.
- Model linking `duni_scalar` to `hash_to_scalar` / ROM.

## Checklist

| Item | Status |
|------|--------|
| `MS_3a_single_branch_schnorr_reparam` | **Proved** (`ms/SchnorrBranch.ec`) from `duni_scalar_shift_reparam` + `in_eq_dlet` + `ms3a_schnorr_reparam_obs_eq` (`sch_sim_announcement_reparam`, `qssm_pair_eq`, `qssm_dunit_eq`) |
| OR-split lemmas | **Proved** |
| `ms_bitness_fs_scalar` / `ms_bitness_fs_programmed` | **Definitions** (`primitives/FS.ec`) |
| `A2_bitness_programmed_challenge` | **Proved** (from `A2_programmable_oracle_exists`) |
| `MS_3a_single_bit_bitness_fs_consistent`, `MS_3a_single_bit_programmed_or_split_exact_simulation` | **Proved** |
| `MS_3a_ordered_challenge_vector_consistency`, `MS_3a_all_bits_from_single_bit` | **Proved** (`ms/BitnessVector.ec`) |
| `MS_3a_bitness_layer_exact_simulation` | **Proved** — for each valid index, unpack `ms_per_bit_programmed` at `ms_nth_single_bit_or bits i`, extract FS+split, and instantiate `MS_3a_single_bit_programmed_or_split_exact_simulation` |
| `MS_3a_observable_bitness_challenges_consistent`, `MS_3a_observable_transcript_digest_consistent` | **Proved** (`ms/TranscriptObservable.ec`) |
| `MS_3a_bitness_layer_to_observable_exact_simulation` | **Proved** — delegates per-index OR packaging through `MS_3a_bitness_layer_exact_simulation`; observable/digest hypotheses reserved for game marginal |
| `d_ms3a_real_payload_seed` | **Defined** (`ms/source/SourcePayloadDistributions.ec`; re-exported **`SourceDistributions`**) as `dmap (dunit (ms3a_make_real_source ms3a_public_stmt_digest x \u2026)) ms3a_real_payload_seed_of_bitness_layer`; matches **`d_ms3a_real_execution_public_seed`** definitionally; bridge **`A_ms3a_real_payload_seed_matches_execution_seed`** is now a **proved lemma** in **`SourceRealExecutionSeed.ec`** |
| `d_ms3a_sim_payload_seed` | **Defined** as `dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer` (same file); **`A_ms3a_spine_sim_marginal_matches_seed`** is a **proved** definitional lemma |
| `d_ms3a_seed_spine_joint` | **Defined** (`ms/source/SourcePayloadDistributions.ec`) as `dunit (ms3a_canonical_public_source x)` (canonical public-spine source); **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**, and **`A_ms3a_seed_spine_support_wf`** are now proved lemmas; the WF lemma reduces to the relocated ROM/FS-layer axiom **`A_ms3a_public_spine_programmed_layer`** in **`ms/SourceModel.ec`** |
| `d_ms3a_real_sim_payload_seed_coupling`, `d_ms3a_coupling_seed_{real,sim}_projection`, `ms3a_real_sim_payload_seed_coupled`, `ms3a_ax_seed_coupling_pair_relation`, `ms3a_ax_seed_support_coupling` | **Definitions** (`ms/source/SourceCouplingTypes.ec`) — joint = `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer` (shared spine, **not** the independent product of abstract **`d_ms3a_real_payload_seed`** with an unrelated sim law — here **`d_ms3a_sim_payload_seed`** is the joint sim marginal **by definition**); pair predicate as before; **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`** proves `ms3a_ax_seed_coupling_pair_relation` from `ms3a_source_wf` on spine support (`SourceCouplingTheorem.ec`); projections fold to `dmap` off the spine (`L_ms3a_coupling_seed_{real,sim}_projection_dmap_spine`); source obligations in **`SourcePayloadDistributions.ec`**: **axioms** **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**, plus **proved lemma** **`A_ms3a_spine_sim_marginal_matches_seed`** (sim seed law is the joint sim marginal **by definition**; **`SourceCouplingAxioms.ec`** summarizes packaging) |
| `d_ms3a_real_source_payload`, `d_ms3a_sim_source_payload` | **Defined** (`ms/source/SourcePayloadDistributions.ec`) as `dmap` pushforwards of seed laws through `ms3a_{real,sim}_payload_from_seed` (`SourceConstructors.ec`) |
| `d_ms3a_bitness_real_source`, `d_ms3a_bitness_sim_source` | **Defined** (`ms/source/SourceBitnessDistributions.ec`) as `dmap` pushforwards of payload laws through `ms3a_bitness_layer_source_of_{real,sim}_payload` (wrappers over `ms3a_make_*_source`) |
| `dmap` preimage / membership for `d_ms3a_bitness_*_source` | **Proved** — `case/supp_dmap` on `Distr.supp_dmap` plus local `distr_mem_eq` (`ms/source/SourceDistributionLemmas.ec`; **MS-3a hardening**, not MS-3b) |
| `ms3a_public_stmt_digest`, `ms3a_public_result_bit`, `ms3a_public_bits`, `ms3a_public_bitness_globals`, `ms3a_public_comparison_global`, `ms3a_public_transcript_digest` | **Abstract ops** (`ms/SourceModel.ec`) — six-field spine from **`ms_public_input`** (no axioms; linking deferred). Consumed by Phase-1 payload constructors in **`SourceConstructors.ec`** |
| `ms3a_public_bitness_shape_ok`, `ms3a_public_transcript_shape_ok` | **Defined preds** (`ms/SourceModel.ec`) — `V2_BIT_COUNT` lengths + **`ms_transcript_digest_of_observable`** on packed spine |
| `ms3a_pack_observable` | **Defined** (`ms/SourceModel.ec`) — canonical v2 packer |
| `d_ms3a_bitness_*_observable_v2`, `d_ms3a_bitness_*_observable`, `ms3a_bitness_real_sim_equiv` (pred), `ms3a_source_observable_equiv_from_layer` | **Defined / proved** (`ms/source/SourceObservableDistributions.ec`) — `dmap` / `dlet` from structured source and abstract pushforward |
| `ms3a_bitness_real_source_as_seed_dmap`, `ms3a_bitness_sim_source_as_seed_dmap` | **Proved** (`SourceBitnessDistributions.ec`) — fold nested payload `dmap`s to a **single** `dmap` off `d_ms3a_{real,sim}_payload_seed` using **`Distr.dmap_comp`** |
| `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`, `L_ms3a_bitness_layer_seed_schedule_composed_form` | **Proved** — `from_seed` is definitional identity, so composed seed maps coincide with **`ms3a_bitness_layer_source_of_{real,sim}_payload`** alone (`SourceBitnessDistributions` / `SourceScheduleSeed`) |
| `ms3a_frame_consistent`, `ms3a_packed_frame` | **Predicates** (`ms/SourceModel.ec`) — reusable frame consistency + packed-field constructor relation |
| `MS_3a_frame_consistent_of_v2` | **Proved** (`ms/SourceModel.ec`) — derives alignment+digest frame from `ms_transcript_digest_of_observable` using `A_ms3a_observable_of_v2_aligns` |
| `MS_3a_exact_bitness_simulation_from_layers` | **Proved** (`ms/source/SourceTheorem.ec`) — reduced to `ms3a_source_observable_equiv_from_layer` using named source-equality premise |
| `MS_3a_exact_bitness_simulation` | **Lemma** (`ms/source/SourceTheorem.ec`) — wrapper now uses named obligations `ms3a_default_source_eq` and `ms3a_default_frame_consistent` (no anonymous admit) |
| `ms3a_real_payload_from_seed_def`, `ms3a_sim_payload_from_seed_def` | **Proved** (`SourceConstructors.ec`) — identity packaging for seed→payload |
| `ms3a_phase1_real_payload_from_public_input`, `ms3a_phase1_sim_payload_from_public_input` | **Defined** (`SourceConstructors.ec`) — nominal real/sim payloads from **`ms3a_public_*`**; same wiring, **not** shared at the type level; independent of abstract **`d_ms3a_*_payload_seed`** until linking |
| `L_ms3a_phase1_payload_pair_public_fields_match`, `ms3a_{real,sim}_payload_from_seed_eq_phase1_of_eq` | **Proved** (`SourceConstructors.ec`) — Phase-1 pair satisfies **`ms3a_payload_pair_public_fields_match`**; identity **`from_seed`** rewrites to Phase-1 when the seed **equals** the Phase-1 record |
| `ms3a_real_payload_programmed_layer_as_bitness_vector` | **Proved** (`SourceConstructors.ec`) — `ms3a_real_payload_programmed_layer p` iff `ms_bitness_vector_programmed_layer` on `p.`ms3rp_stmt / bits / bitness globals |
| `ms3a_public_bits_of_execution`, `ms3a_public_bitness_global_digest_of_execution`, `ms3a_public_bitness_globals_of_execution`, `ms3a_public_bits_shape_of_execution`, `ms3a_public_bitness_globals_ordered_of_execution`, `ms3a_public_bits_per_bit_programmed_of_execution` | **Defined constructors + proved local lemmas** (`SourcePublicBitnessConstructors.ec`) — concrete list-level constructor boundary on `ms3a_bitness_layer_source`; ordered globals are definitionally the digest map of each bit transcript's global challenge, shape/ordered-global lemmas are purely structural, and the per-bit constructor lemma follows from `ms3a_source_wf`. |
| `ms3a_public_bitness_execution`, `ms3a_public_bitness_vector_programmed_of_public_bitness_execution` | **Defined predicate + proved projection lemma** (`SourcePublicBitnessExecution.ec`) — one source-side public-bitness execution predicate packages shape, per-index stmt/programmed-transcript facts, and ordered bitness-global digest equality; this file is now generic and exports only the implication from that predicate to `ms_bitness_vector_programmed_layer`. |
| `ms3a_game_public_bitness_source`, `d_ms3a_real_execution_bitness_source`, `d_ms3a_real_execution_public_seed` | **Defined** (`SourceRealExecutionGameLink.ec`) — deterministic public source record, point-mass source sampler, and concrete real execution public-seed law `dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer` |
| `ms3a_game_public_bitness_source_projects_public_spine`, `ms3a_real_execution_public_seed_support_inv`, `ms3a_real_execution_bitness_source_public_fields_on_support`, `ms3a_game_real_execution_seed_public_fields` | **Proved structural lemmas** (`SourceRealExecutionGameLink.ec`) — structural `dunit`/`dmap` consequences for the concrete game source and execution seed law |
| `A_ms3a_real_payload_seed_matches_execution_seed` | **Axiom** (`SourceRealExecutionSeed.ec`) — bridge equating the abstract real seed law with the concrete execution-seed law. |
| `ms3a_game_public_bitness_source_on_spine_support`, `ms3a_game_public_bitness_source_wf`, `ms3a_public_bits_per_bit_programmed_of_game_execution`, `ms3a_public_bitness_globals_ordered_of_game_execution`, `ms3a_public_bitness_execution_of_game_execution`, `ms3a_public_bitness_vector_programmed_of_game_execution`, `ms3a_real_execution_seed_link_of_game_execution` | **Proved theorems** (`SourceRealExecutionSeed.ec`) — the existing real-seed bridge plus the spine-marginal/WF axioms place the concrete game source on abstract spine support, recover `ms3a_source_wf`, prove the full public-bitness execution theorem, and then derive the execution-seed link theorem. |
| `A_ms3a_public_payload_bitness_programmed` | **Proved lemma** (`SourceProgrammedObligations.ec`) — recovered from `ms3a_real_execution_seed_link_of_game_execution` via `ms3a_public_payload_bitness_programmed_of_execution_seed_law`; no standalone programmed-layer axiom remains in this file. |
| `A_ms3a_real_seed_bitness_fields_are_public_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — recovered from `ms3a_real_execution_seed_link_of_game_execution` + `A_ms3a_real_payload_seed_matches_execution_seed` via `ms3a_real_seed_public_fields_on_support_of_execution_seed_law`; no standalone projection axiom remains in this file. |
| `ms3a_execution_public_spine_link`, `ms3a_real_execution_seed_link` | **Defined predicates / package surface** (`SourceExecutionLink.ec`, `SourceRealExecutionSeed.ec`) — source-facing and execution-facing wrappers for the same public-spine/programmed facts, with the latter now the single semantic package consumed downstream. |
| `ms3a_public_payload_bitness_programmed_of_execution_link`, `ms3a_real_seed_public_fields_on_support_of_execution_link`, `ms3a_public_payload_bitness_programmed_of_execution_seed_law`, `ms3a_real_seed_public_fields_on_support_of_execution_seed_law` | **Proved projection / bridge lemmas** (`SourceExecutionLink.ec`, `SourceRealExecutionSeed.ec`) — recover the exact theorem shapes used by `SourceProgrammedObligations.ec`, which now proves the old names as lemmas. |
| `A_ms3a_sim_seed_bitness_fields_are_public_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — sim support is definitionally `dmap` support off `d_ms3a_seed_spine_joint`; collapsing a supported sim seed to a spine sample and reusing the existing real marginal + real projection facts yields the public stmt / bits / bitness globals equalities. **Status A:** collapsed this phase; no replacement axiom needed. |
| `A_ms3a_real_seed_bits_programmed_on_support`, `A_ms3a_real_seed_bitness_globals_programmed_on_support` | **Proved lemmas** (`SourceProgrammedObligations.ec`) — from `A_ms3a_public_payload_bitness_programmed` + `A_ms3a_real_seed_bitness_fields_are_public_on_support` + `MS_3a_all_bits_from_single_bit` (`BitnessVector.ec`) |
| `A_ms3a_real_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — from the two real **lemmas** above + unfolds |
| `ms3a_sim_payload_programmed_layer_as_bitness_vector` | **Proved** (`SourceConstructors.ec`) — `ms3a_sim_payload_programmed_layer p` iff `ms_bitness_vector_programmed_layer` on `p.`ms3sp_stmt / bits / bitness globals |
| `A_ms3a_sim_seed_bits_programmed_on_support`, `A_ms3a_sim_seed_bitness_globals_programmed_on_support` | **Proved lemmas** (`SourceProgrammedObligations.ec`) — from `A_ms3a_public_payload_bitness_programmed` + proved lemma `A_ms3a_sim_seed_bitness_fields_are_public_on_support` + `MS_3a_all_bits_from_single_bit` (`BitnessVector.ec`) |
| `A_ms3a_sim_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — from the two sim **lemmas** above + unfolds |
| `ms3a_payload_pair_stmt_eq_from_seed_of_seed_stmt_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` statement field equals seed `ms3rp_stmt` / `ms3sp_stmt` when those agree |
| `ms3a_payload_pair_res_eq_from_seed_of_seed_res_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` result field equals seed `ms3rp_res` / `ms3sp_res` when those agree |
| `ms3a_payload_pair_comparison_global_challenge_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` comparison-global digest equals seed fields when those agree |
| `ms3a_payload_pair_bitness_global_challenges_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` bitness-global lists equal seed fields when those agree |
| `L_ms3a_seed_pair_{stmt,res,comparison_global,bitness_globals}_when_seeds_are_phase1` | **Proved** (`SourcePublicFieldObligations.ec`) — same four conclusions as **`A_ms3a_seed_pair_*_source_shared`** when joint-support seeds **are** the Phase-1 spine records (membership hypotheses unused in proof) |
| `A_ms3a_seed_pair_stmt_source_shared` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — by projecting the `stmt` field out of **`A_ms3a_seed_pair_public_fields_match_on_support`** |
| `A_ms3a_seed_pair_stmt_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` stmt equality, from `A_ms3a_seed_pair_stmt_source_shared` + identity |
| `A_ms3a_seed_pair_res_source_shared` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — same pattern with **`L_ms3a_payload_pair_res_seed_of_bitness`** |
| `A_ms3a_seed_pair_res_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` res equality, from `A_ms3a_seed_pair_res_source_shared` + identity |
| `A_ms3a_seed_pair_comparison_global_source_shared` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — **`L_ms3a_payload_pair_comparison_global_seed_of_bitness`** |
| `A_ms3a_seed_pair_comparison_global_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` comparison-global equality, from source-shared + identity |
| `A_ms3a_seed_pair_bitness_globals_source_shared` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — **`L_ms3a_payload_pair_bitness_globals_seed_of_bitness`** |
| `A_ms3a_seed_pair_bitness_globals_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` bitness-global list equality, from source-shared + identity |
| `A_ms3a_seed_pair_public_fields_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — combines four `*_on_support` lemmata |

## All-bit bitness lift (`ms/BitnessVector.ec`)

**Status (MS-3a vector layer):** **wired** — definitions and composition predicates in place (`V2_BIT_COUNT = 64`, per-bit programmed transcript, ordered global challenge digest vector, `ms_transcript_bitness_digests_match_vector`). List order models ordered `ms_bitness_global_challenges` / execution-spec bitness challenge vector.

**Single-bit FS + OR layer:** **complete** (`ms/BitnessOne.ec` + `primitives/FS.ec` hooks).

## Transcript observable layer (`ms/TranscriptObservable.ec` + `ms/SourceModel.ec`)

**Canonical record** `ms_v2_transcript_observable` (statement digest, result bit, `msv2_bitness_global_challenges`, comparison digest, transcript digest).

**Relations:** `ms_bitness_vector_matches_observable` (bitness list + stmt + result), `ms_transcript_digest_of_observable` (digest cell vs abstract `ms_transcript_digest_public_fields`).

**Abstract link + packaging:** `ms_abstract_observable_aligns_v2`, `ms3a_observable_of_v2`, `ms3a_pack_observable`, and `ms3a_packed_frame` in `ms/SourceModel.ec` tie canonical v2 observables to the abstract transcript surface.

## MS-3a global statement (layered)

- **`MS_3a_exact_bitness_simulation_from_layers`** — hypotheses track single-branch reparam, OR-split, A2 bitness ROM corollary, vector bitness layer, observable bridge, and **`ms3a_frame_consistent obs o`**; proof closes via **`ms3a_source_observable_equiv_from_layer`** plus a named source-equality premise.
- **`MS_3a_exact_bitness_simulation`** — applies the skeleton with concrete lemma proof terms; `ms3a_default_source_eq` is now **proved** by **`ms3a_source_eq_from_bitness_layer`**, which unfolds folded `d_ms3a_bitness_*_source` to payload `dmap`s and applies lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`** (proved from lemma **`A_ms3a_bitness_layer_seed_schedule`** + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`ms3a_bitness_{real,sim}_source_as_seed_dmap`**; no `ms3a_ax_*` premises). Lemma **`A_ms3a_bitness_layer_seed_schedule`** is **proved** from **`A_ms3a_spine_real_marginal_matches_seed`** (axiom) and **`A_ms3a_spine_sim_marginal_matches_seed`** (**proved** definitional lemma) by rewriting marginals, folding nested `dmap`s with **`Distr.dmap_comp`**, then **`eq_dmap_in`** with definitional inversion of the composed layer maps on the spine carrier. The five `ms3a_ax_*` predicates are still used by mem-pair lemmas and are **proved lemmas** (`ms3a_ax_*_from_payload_support` / `*_from_real_sim_wf` in `SourceSchedulePayload.ec`, re-exported via `SourceScheduleObligations.ec`; packaged as `ms3a_ax_*_from_axioms` in `SourceTheorem.ec`) **derived from** the three **payload-support lemmas** alone; those payload-support lemmas are in turn **proved** from the **seed-level** programmed axioms plus the four **`A_ms3a_seed_pair_*_source_shared`** lemmas (not added as parallel hypotheses). Concretely: **`ms3a_payload_{real,sim}_support_programmed`** use **`A_ms3a_{real,sim}_seed_programmed_on_support`**, each proved from its two programmed-field axioms; **`ms3a_payload_pair_public_fields_on_support`** uses **`A_ms3a_seed_pair_public_fields_on_support`**, proved by conjoining the four **`A_ms3a_seed_pair_*_on_support`** lemmas, each proved from the matching **`A_ms3a_seed_pair_*_source_shared`** lemma and identity `from_seed`. **Proved** constructor lemmas (`ms3a_real_source_constructor_wf`, …) in `ms/source/SourceScheduleTheorem.ec` consume those payload-support lemmas and **`MS_3a_bitness_layer_exact_simulation`**. Mem-pair lemmas live in `ms/source/SourceTheorem.ec`. Constructor lemmas `ms3a_pack_observable_with_digest_consistent`, `ms3a_default_transcript_digest_consistent`, and `ms3a_default_frame_consistent` keep frame wiring explicit (no anonymous admits).

`theorem/MainTheorem.ec` **`use_MS_3a`** is a **lemma** returning **`ms3a_bitness_real_sim_equiv x s`** (imports `SourceDistributions` + `SourceTheorem`).

### Remaining proof obligations (MS-3a track; axioms, not `admit`)

There is **no** `admit` left in `docs/03-formal-verification/easycrypt/*.ec`.

| Obligation | Where |
|------------|--------|
| Uniform-shift reparameterization for `duni_scalar` joint pairs | **Axiom** `duni_scalar_shift_reparam` (`ms/SchnorrBranch.ec`) |
| Spine real marginal + WF + paired-public support | **Axioms** `A_ms3a_spine_real_marginal_matches_seed`, `A_ms3a_seed_spine_support_wf`, `A_ms3a_seed_pair_public_fields_match_on_support` (`ms/source/SourcePayloadDistributions.ec`) — game-level discharge once `d_ms3a_seed_spine_joint` / `d_ms3a_real_payload_seed` are instantiated |
| Spine sim marginal | **Lemma** `A_ms3a_spine_sim_marginal_matches_seed` — **proved** (definitional): `d_ms3a_sim_payload_seed` is `dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer` |
| Seed-level bitness-layer schedule (single `dmap` per side off abstract seeds) | **Lemma** `A_ms3a_bitness_layer_seed_schedule` (`ms/source/SourceScheduleSeed.ec`) — **proved** equality `dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload = dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload` from **`A_ms3a_spine_real_marginal_matches_seed`** + **`A_ms3a_spine_sim_marginal_matches_seed`** + **`Distr.dmap_comp`** + **`eq_dmap_in`** (see “Schedule (seed boundary)” below). **Proved packaging:** `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap` (`SourceBitnessDistributions.ec`) and `L_ms3a_bitness_layer_seed_schedule_composed_form` (`SourceScheduleSeed.ec`) recover the legacy **`… \o ms3a_*_payload_from_seed`** statement |
| Payload-level `dmap` schedule (nested payload pushforwards) | **Lemma** `A_ms3a_payload_dmap_bitness_layer_schedule` (`SourceSchedulePayload.ec`) — **proved** from `A_ms3a_bitness_layer_seed_schedule` + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`ms3a_bitness_{real,sim}_source_as_seed_dmap`**. **`ms3a_payload_schedule_equivalence`** — **deprecated / compatibility wrapper** (proved; redundant `ms3a_ax_*` hypotheses unused in proof). **`ms3a_source_eq_from_bitness_layer`** — **proved** in `SourceScheduleTheorem.ec` without those hypotheses |
| `ms3a_ax_real_wf`, `ms3a_ax_sim_wf`, `ms3a_ax_public_fields`, `ms3a_ax_prog_layer`, `ms3a_ax_bitness_exact` | **Proved lemmas** from payload-support lemmas + `dmap`/`supp_dmap` (`SourceSchedulePayload.ec`; facade `SourceScheduleObligations.ec`); **`ms3a_ax_*_from_axioms`** in `SourceTheorem.ec` |
| Seed support (programmed layer on **seed** support) | **Lemmas** `A_ms3a_real_seed_programmed_on_support`, `A_ms3a_sim_seed_programmed_on_support` from four proved **lemmas** (`A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support`; `ms/source/SourceProgrammedObligations.ec`), derived from the proved real support lemmas `A_ms3a_public_payload_bitness_programmed` and `A_ms3a_real_seed_bitness_fields_are_public_on_support`, which are themselves discharged from `A_ms3a_real_execution_seed_link` + `A_ms3a_real_payload_seed_matches_execution_seed`, together with the proved sim projection lemma `A_ms3a_sim_seed_bitness_fields_are_public_on_support` |
| Seed support (paired **public** fields on seed support) | **Proved lemmas** `A_ms3a_seed_pair_stmt_source_shared`, `A_ms3a_seed_pair_res_source_shared`, `A_ms3a_seed_pair_comparison_global_source_shared`, `A_ms3a_seed_pair_bitness_globals_source_shared` (`ms/source/SourcePublicFieldObligations.ec`) by projection from **`A_ms3a_seed_pair_public_fields_match_on_support`**; **lemmata** `A_ms3a_seed_pair_stmt_on_support`, …, `A_ms3a_seed_pair_bitness_globals_on_support`; **lemma** `A_ms3a_seed_pair_public_fields_on_support` combines into `ms3a_payload_pair_public_fields_match` for `from_seed` |
| Payload support (programmed layer on payload support) | **Proved lemmas** `ms3a_payload_real_support_programmed`, `ms3a_payload_sim_support_programmed` (`ms/source/SourcePublicFieldObligations.ec`) — from real/sim programmed lemmas + defining `dmap` + `supp_dmap` |
| Payload public fields on paired payload support | **Proved lemma** `ms3a_payload_pair_public_fields_on_support` (`ms/source/SourcePublicFieldObligations.ec`); bridge **`ms3a_real_sim_public_fields_of_payload_pair`** is **proved** (`ms/source/SourceDistributionLemmas.ec`) |
| Constructor-scoped source obligations | **Proved lemmas** `ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact` (`ms/source/SourceScheduleTheorem.ec`) |
| Source-constructor image predicates | `ms3a_real_source_in_constructor_image`, `ms3a_sim_source_in_constructor_image` — **definitions** (`ms/source/SourceDistributionLemmas.ec`) |
| Source distribution-in-image | `ms3a_real_source_distribution_in_image`, `ms3a_sim_source_distribution_in_image` — **proved** from `dmap` source definitions + `supp_dmap` / `distr_mem_eq` (`ms/source/SourceDistributionLemmas.ec`) |
| Source constructor image lemmas | `ms3a_real_source_constructor_image`, `ms3a_sim_source_constructor_image` — **proved** (delegate to distribution-in-image lemmas) (`ms/source/SourceDistributionLemmas.ec`) |
| Generic digest-by-construction constructor field/layout obligation | `ms3a_pack_observable_with_digest_field_correct` (`ms/SourceModel.ec`) |
| Skeleton-to-game equivalence (`ms3a_bitness_real_sim_equiv` to full game statement) | future `QssmGames` / transcript ops (explicitly out of current scope) |

### Schedule (seed boundary)

**Lemma (seed boundary):** **`A_ms3a_bitness_layer_seed_schedule`** is the **unconditional** equality of the **one-step** pushforwards
`dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload =
 dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload`.
It is **proved** in **`SourceScheduleSeed.ec`** by rewriting both marginals with
**`A_ms3a_spine_real_marginal_matches_seed`** and **`A_ms3a_spine_sim_marginal_matches_seed`**, folding nested `dmap`s with **`Distr.dmap_comp`**, then
**`eq_dmap_in`** with definitional inversion of **`ms3a_bitness_layer_source_of_{real,sim}_payload \o ms3a_{real,sim}_payload_seed_of_bitness_layer`** on spine samples.
Because **`ms3a_{real,sim}_payload_from_seed`** are **definitional identities** on the
payload-shaped seed types, the older composed form
`dmap (d_ms3a_*_payload_seed …) (ms3a_bitness_layer_source_of_* \o ms3a_*_payload_from_seed …)`
is **proved equivalent** (`eq_dmap_in`) by **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`**
(`SourceBitnessDistributions.ec`); lemma **`L_ms3a_bitness_layer_seed_schedule_composed_form`**
packages **`A_ms3a_bitness_layer_seed_schedule`** back into that legacy shape. Payload laws are **defined** as
`dmap (d_ms3a_*_payload_seed) (ms3a_*_payload_from_seed …)`, so (by **`Distr.dmap_comp`**) folded
`d_ms3a_bitness_{real,sim}_source` matches the composed seed pushforwards. Lemma
**`A_ms3a_payload_dmap_bitness_layer_schedule`** recovers the older **payload-nested** phrasing for
compatibility and for call sites that still speak in terms of `d_ms3a_*_source_payload`.

**Conceptual decomposition (for proof planning, not separate axioms):**

1. **Real payload pushforward shape** — proved: `ms3a_bitness_real_source_as_seed_dmap`.
2. **Sim payload pushforward shape** — proved: `ms3a_bitness_sim_source_as_seed_dmap`.
3. **Identity collapse on seeds** — proved: `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`.
4. **Common bitness-layer image** — the **equality** of the two seed pushforwards (layer maps off abstract seeds) is lemma **`A_ms3a_bitness_layer_seed_schedule`**, **proved** from **`A_ms3a_spine_real_marginal_matches_seed`** + **`A_ms3a_spine_sim_marginal_matches_seed`** (the latter **proved** definitional) plus `dmap` algebra (still a **proof obligation** at game level to discharge the **real** marginal axiom and the WF / paired-public-support axioms).
5. **Public-field alignment** — **`A_ms3a_seed_pair_*_source_shared`** are **proved lemmas** by projecting **`A_ms3a_seed_pair_public_fields_match_on_support`** (they still do **not** imply the schedule alone: they omit **`ms3rp_transcript_digest` / `ms3sp_transcript_digest`**, so transcript-digest coupling is **not** captured by the four paired-public facts alone).

**Tradeoff:** the schedule statement remains **unconditional** on `ms3a_ax_*` (those five predicates stay **proved lemmas**
from payload-support lemmas (from programmed seed axioms + `source_shared` lemmas), not schedule side-conditions).

**`ms3a_payload_schedule_equivalence`:** treat as **legacy / wrapper** packaging
only. New proofs should cite **`A_ms3a_bitness_layer_seed_schedule`**, lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`**, or **`ms3a_source_eq_from_bitness_layer`**; do not read the five `ms3a_payload_schedule_equivalence` hypotheses as part of the schedule proof obligation.

## Seed distribution concretization (design audit)

This section records **what must become concrete** so abstract
`d_ms3a_real_payload_seed` and the spine joint can eventually discharge the remaining MS-3a
**axioms** (three public-spine / projection facts for programmed-on-support, three source axioms — real marginal / WF / paired-public support — plus abstract joint), without editing `.ec` proofs here. (**`d_ms3a_sim_payload_seed`** is now **defined** from the joint; the old sim marginal axiom is a **proved** lemma.)

### Spine bridge obligations (what is still axiomatic)

**Reduction (in-repo):** **`d_ms3a_sim_payload_seed x s`** is **defined** as
`dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer`, so the former
**sim marginal bridge** is **`A_ms3a_spine_sim_marginal_matches_seed`**, now a **proved** lemma
(`by []`). The **`(x,s)`** indexing is coherent: joint and sim marginal share the same sim seed
parameter.

**Still abstract (no fake proofs):** **`d_ms3a_seed_spine_joint`** and **`d_ms3a_real_payload_seed`**
have no defining bodies. The **real** marginal equality **`A_ms3a_spine_real_marginal_matches_seed`**
cannot be eliminated by the same definitional trick: **`d_ms3a_real_payload_seed x`** does not carry
**`s`**, while `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer` **does**
depend on **`s`** unless a separate game-level lemma proves **`s`**-independence of that `dmap`
(and then one could **define** the real law from any fixed **`s`** only after such a lemma — not
done here).

**Remaining axioms:** **`A_ms3a_spine_real_marginal_matches_seed`** (ties abstract real law to the
joint’s real marginal for every **`s`**), **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`**.

**Status of `A_ms3a_spine_real_marginal_matches_seed` (real marginal bridge):** **blocked** on
either (i) a game-level **`s`**-independence proof for **`dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer`**, or (ii) a canonical-real-marginal definition pinning
**`d_ms3a_real_payload_seed x`** to one fixed **`s0`** spine marginal (the latter would require
extending the abstract op’s definition; **`d_ms3a_real_payload_seed`** is consumed unchanged at
14+ call sites). Substituting a narrower obligation **`A_ms3a_spine_real_marginal_independent_of_s`**
was considered and **not adopted**: it does not reduce debt — it would still require a second
bridge identifying one canonical spine marginal with the abstract op (1 axiom → 2 axioms).
The bridge therefore remains an axiom under its current statement.

**Status of `A_ms3a_seed_spine_support_wf` (spine support WF):** **unchanged**. A direct proof is
blocked for the same structural reason as other spine-side obligations: **`d_ms3a_seed_spine_joint`**
is still abstract, so `src \in d_ms3a_seed_spine_joint x s` exposes no constructor fields to
rewrite. A narrower consumed invariant was **not** isolated: **`ms3a_source_wf`** already unfolds
exactly to **`ms_bitness_vector_programmed_layer src.`ms3s_stmt src.`ms3s_bits
src.`ms3s_bitness_global_challenges`**, and the only checker-visible consumer,
**`L_ms3a_real_sim_seed_of_bitness_coupled_of_wf`** in `SourceCouplingTheorem.ec`, needs exactly
that programmed-bitness fact for the last two conjuncts of
**`ms3a_real_sim_payload_seed_coupled`**. Replacing the axiom with a “support has programmed
bitness vector” axiom would only rename the same predicate, so this phase lands as **Status C**.

**Status of `A_ms3a_public_payload_bitness_programmed` (public-payload programmed bridge):**
**unchanged**. This is the root public-spine programmed predicate, and the real/sim seed-support
lemmas in `SourceProgrammedObligations.ec` consume it only through
`MS_3a_all_bits_from_single_bit`, together with the two projection-to-public-field axioms.
There is no narrower public-payload support law in the current interface: `ms3a_public_*` in
`SourceModel.ec` are uninterpreted projections, `ms3a_public_bitness_shape_ok` proves only list
lengths, and no local constructor/public-field equality lemma yields
`ms_bitness_vector_programmed_layer (ms3a_public_stmt_digest x) (ms3a_public_bits x)
 (ms3a_public_bitness_globals x)`. Splitting the axiom into per-bit and ordered-vector facts
would increase axiom count, so this phase also lands as **Status C**: true execution / ROM / FS
semantic debt.

**Status of `A_ms3a_real_seed_bitness_fields_are_public_on_support` (real-seed public-field
projection):** **unchanged**. The real seed record certainly carries `stmt` / `bits` /
`bitness_global_challenges` as direct fields, and `ms3a_real_payload_from_seed` is just the
identity, but support of **`d_ms3a_real_payload_seed x`** is still abstract. Membership
`sigma \in d_ms3a_real_payload_seed x` therefore exposes no constructor or phase-1 witness, and
the current file set has no lemma relating arbitrary real-seed support to
`ms3a_phase1_real_payload_from_public_input x` or to a spine preimage without using the already
blocked real-marginal story. A candidate narrowing to seeds of the form
**`ms3a_real_payload_seed_of_bitness_layer src`** was rejected: making that useful for arbitrary
`sigma \in d_ms3a_real_payload_seed x` would require the real marginal bridge and an additional
public-spine/source projection fact, increasing rather than reducing debt. This phase therefore
also lands as **Status C**.

**Status of `A_ms3a_sim_seed_bitness_fields_are_public_on_support` (sim-seed public-field
projection):** **collapsed to a lemma**. Unlike the real side,
**`d_ms3a_sim_payload_seed x s`** is definitionally
**`dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer`**, so
`sigma \in d_ms3a_sim_payload_seed x s` can be inverted with `supp_dmap` to a spine sample
`src` together with `sigma = ms3a_sim_payload_seed_of_bitness_layer src`. Pushing that same
`src` through **`A_ms3a_spine_real_marginal_matches_seed`** yields supported real seed
`ms3a_real_payload_seed_of_bitness_layer src`, and the existing real projection axiom
**`A_ms3a_real_seed_bitness_fields_are_public_on_support`** fixes its `stmt` / `bits` /
`bitness_global_challenges` to the public spine. Since the real and sim constructor images copy
those three fields from the same `src`, the sim equalities follow by definitional rewriting.
This phase therefore lands as **Status A**: one axiom removed, no replacement introduced.

**Execution/public-payload linkage audit:** local MS-3a narrowing is now **mostly exhausted**.
At that stage, the two programmed-layer facts still sat above `ms/source/` and were not blocked by a
missing local projection rewrite. Today, `GameTypes.ec` / `GameViews.ec` only package `xms`
into `G_MS_*` with **`msgv_ms_obs = witness`**; `GameMSHopTypes.ec` and
`GameMSHopTransitions.ec` only package stage premises and hop bounds; `game_pr` remains an
abstract op in `GameAdvantage.ec`; `ms_real_transcript` / `ms_sim_transcript` in `MS.ec` are
shell views; and `sim/Simulator.ec` exposes only abstract simulator/extractor ops plus the
vacuous placeholder `simulate_qssm_transcript_public_only`. There is therefore no existing
execution definition of public input generation, bitness transcript generation, transcript
digest wiring, or real-seed sampling to mine for a local proof.

The closest in-tree candidates are the deterministic constructor
`ms3a_phase1_real_payload_from_public_input`, the abstract interfaces `ms_simulator` /
`extract_ms_public`, and the witness-only game shells `G_MS_*` / `ms_real_transcript`; none of
them samples or computes the real MS-3a seed law.

**Smallest future bridge package identified by this audit:**

1. **Public-spine programmed theorem.** Add an execution/game linkage theorem stating that the
  canonical MS-3a public spine carried by `x : ms_public_input` satisfies
  `ms_bitness_vector_programmed_layer (ms3a_public_stmt_digest x) (ms3a_public_bits x)
  (ms3a_public_bitness_globals x)`. This is the exact semantic bridge needed to discharge
  **`A_ms3a_public_payload_bitness_programmed`**. Existing definitions in `FS.ec`,
  `BitnessOne.ec`, and `BitnessVector.ec` already define the target predicate precisely
  (`ms_bitness_fs_scalar`, `ms_bitness_fs_programmed`, `ms_per_bit_programmed`,
  `ms_ordered_challenge_vector_matches`); what is missing is a theorem that the **actual**
  game/execution-produced public fields satisfy it.

2. **Real-seed/public-spine linkage.** Add a theorem or concrete marginal law stating that every
  `sigma \in d_ms3a_real_payload_seed x` has
  `sigma.`ms3rp_stmt = ms3a_public_stmt_digest x`,
  `sigma.`ms3rp_bits = ms3a_public_bits x`, and
  `sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x`.
  The strongest and most reusable form would define `d_ms3a_real_payload_seed x` as a real
  marginal of a concrete execution/spine distribution rather than as a standalone support law.
  In its support-only form this discharges **`A_ms3a_real_seed_bitness_fields_are_public_on_support`**;
  in its marginal form it is also the natural route to discharging
  **`A_ms3a_spine_real_marginal_matches_seed`**.

The recommended minimal new definition is therefore a real execution public-seed distribution
such as `d_ms3a_real_execution_public_seed x : ms3a_real_payload_seed distr`, with
`d_ms3a_real_payload_seed x` later instantiated from it or proved equal to it. A pure
`ms3a_execution_public_spine x` alias would be weaker and mostly duplicate the existing Phase-1
payload constructor without adding the missing sampler semantics.

**Conclusion of this audit:** the smallest next implementation target is **not** another
`ms/source/` lemma. It is the first concrete execution/game bridge that connects the stage-tagged
`G_MS_*` views and abstract `ms_public_input` carrier to actual MS-3a bitness transcript fields
and real seed support.

**Real execution-seed bridge added:** `ms/source/SourceRealExecutionSeed.ec` now introduces the
abstract concrete-boundary law `d_ms3a_real_execution_public_seed x`, packages the two execution
facts in predicate `ms3a_real_execution_seed_link x`, proves the projection lemmas
`ms3a_public_payload_bitness_programmed_of_real_execution_seed_link` and
`ms3a_real_seed_public_fields_on_support_of_real_execution_seed_link`, adds bridge axiom
`A_ms3a_real_payload_seed_matches_execution_seed`, adds package axiom
`A_ms3a_real_execution_seed_link`, and derives theorem-shape lemmas
`ms3a_public_payload_bitness_programmed_of_execution_seed_law`,
`ms3a_real_seed_public_fields_on_support_of_execution_seed_law`, and
`ms3a_execution_public_spine_link_of_execution_seed_law`. `SourceProgrammedObligations.ec`
now imports this theory and replaces `A_ms3a_public_payload_bitness_programmed` and
`A_ms3a_real_seed_bitness_fields_are_public_on_support` with proved lemmas of the same names.

**Real-seed wiring audit result:** direct definition of `d_ms3a_real_payload_seed x` from
`d_ms3a_real_execution_public_seed x` is semantically compatible with the current consumers, but
it is **not** a trivial local patch in the present layering. Support/projection users
(`SourceExecutionLink.ec`, most of `SourceProgrammedObligations.ec`,
`SourcePublicFieldObligations.ec`) would tolerate either option. Exact-distribution consumers
(`SourceBitnessDistributions.ec`, `SourceScheduleSeed.ec`, `SourceCouplingTypes.ec`) already rely
on equalities phrased over `d_ms3a_real_payload_seed`, so they stay cleanest if the old name
remains the surface seen by the schedule/coupling chain. The preferred immediate wiring was
therefore **Option B**, and that bridge is now present as axiom
`A_ms3a_real_payload_seed_matches_execution_seed`. Net MS-3a named axiom count is now **5**:
the spine trio plus the execution-seed bridge axiom `A_ms3a_real_payload_seed_matches_execution_seed`
and the centralized package axiom `A_ms3a_real_execution_seed_link`. The remaining semantic debt is
no longer split across `SourceProgrammedObligations.ec`; it is centralized in `SourceRealExecutionSeed.ec`,
and the remaining blocker is no longer import direction; it is the lack of an unconditional theorem or
axiom establishing `ms3a_real_execution_seed_link x`.

**Recorded theorem-design skeleton:** `SourceRealExecutionSeed.ec` now records the exact target
theorem name `ms3a_real_execution_seed_link_of_game_execution : forall x,
ms3a_real_execution_seed_link x` as a comment-only proof map. The intended local decomposition is:

- `ms3a_game_public_spine_programmed` — prove
  `ms_bitness_vector_programmed_layer (ms3a_public_stmt_digest x)
   (ms3a_public_bits x) (ms3a_public_bitness_globals x)` for every `x`.
- `ms3a_game_real_execution_seed_public_fields` — prove every
  `sigma \in d_ms3a_real_execution_public_seed x` matches the same public stmt / bits /
  bitness-global fields.

The current blocker is still concrete execution semantics: no theorem presently ties a sampled
transcript/public spine to `ms3a_public_*`, no FS/ROM derivation theorem proves the public spine is
programmed, and no support lemma exists yet for the concrete law
`d_ms3a_real_execution_public_seed`.

This phase adds the minimal concrete boundary:

- new theory **`ms/source/SourceRealExecutionGameLink.ec`** above `SourceRealExecutionSeed.ec`
- deterministic source object
  **`ms3a_game_public_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source`**
- concrete source sampler
  **`d_ms3a_real_execution_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source distr`**
- implemented seed law
  **`d_ms3a_real_execution_public_seed x = dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer`**

This is the smallest object set that covers both recorded subgoals without adding another abstract
wrapper: the source record already carries stmt / result / bits / bitness globals / comparison
global / transcript digest together, and the existing constructor lemmas in `SourceConstructors.ec`
already map that record into the current seed type.

The proved local structural theorem names are:

- **`ms3a_game_public_bitness_source_projects_public_spine`**
- **`ms3a_real_execution_public_seed_support_inv`**
- **`ms3a_real_execution_bitness_source_public_fields_on_support`**
- **`ms3a_game_real_execution_seed_public_fields`**

The remaining local semantic theorem names are:

- **`ms3a_game_public_bits_per_bit_programmed`**
- **`ms3a_game_public_bitness_globals_ordered`**

Public-bits ROM/FS boundary result:

- expanding **`ms3a_game_public_bits_per_bit_programmed`** reaches `ms_per_bit_programmed`, so for every valid bit index the corresponding element of **`ms3a_public_bits x`** must expose stmt/public-point/branch/challenge fields satisfying **`ms_single_bit_programmed_bitness_transcript`**
- **`FS.ec`** supplies only the query/scalar surface (**`ms_bitness_query_digest`**, **`ms_query_to_scalar`**, **`ms_bitness_fs_scalar`**, **`ms_bitness_fs_programmed`**, **`A2_bitness_programmed_challenge`**)
- **`BitnessOne.ec`** and **`BitnessVector.ec`** package and consume those predicates, but do not construct **`ms3a_public_bits x`** or prove that the public vector comes from a concrete execution/ROM trace
- no MS/game/simulator surface currently carries a concrete MS observable or per-bit list: `ms_real_transcript`, `ms_sim_transcript`, and the `G_MS_after_*` views keep `msgv_ms_obs = witness`, while `ms_simulator` / `extract_ms_public` remain abstract
- implemented as **`ms/source/SourcePublicBitnessExecution.ec`** with one package predicate **`ms3a_public_bitness_execution`** and the generic projection theorem **`ms3a_public_bitness_vector_programmed_of_public_bitness_execution`**
- **`ms/source/SourcePublicBitnessConstructors.ec`** proves the structural constructor lemmas **`ms3a_public_bits_shape_of_execution`** and **`ms3a_public_bitness_globals_ordered_of_execution`**, and packages **`ms3a_public_bits_per_bit_programmed_of_execution`** under **`ms3a_source_wf`**
- `SourceRealExecutionSeed.ec` now proves **`ms3a_game_public_bitness_source_on_spine_support`**, **`ms3a_game_public_bitness_source_wf`**, **`ms3a_public_bitness_execution_of_game_execution`**, **`ms3a_public_bitness_vector_programmed_of_game_execution`**, and **`ms3a_real_execution_seed_link_of_game_execution`** using the existing real-seed bridge axiom plus the spine-marginal/WF axioms; no extra globals bridge axiom was needed
- the remaining next step is no longer public-bitness closure; it is to replace **`A_ms3a_real_payload_seed_matches_execution_seed`** if the exact real-seed law becomes concrete first

Together they should feed the already recorded goal **`ms3a_game_public_spine_programmed`** and
**`ms3a_game_real_execution_seed_public_fields`**, and then theorem
**`ms3a_real_execution_seed_link_of_game_execution`**. This step is now complete: the public-bitness
boundary proves the missing FS/ROM-facing corollaries, and `SourceRealExecutionSeed.ec` no longer
needs `A_ms3a_real_execution_seed_link`.

### Execution/link skeleton boundary

**This phase adds** **`ms/source/SourceExecutionLink.ec`** as the smallest clean theory boundary.
It does **not** replace any existing axiom yet. Instead it packages the two remaining theorem
targets into one predicate:

- **`ms3a_execution_public_spine_link (x : ms_public_input)`**
  means:
  `ms_bitness_vector_programmed_layer
     (ms3a_public_stmt_digest x)
     (ms3a_public_bits x)
     (ms3a_public_bitness_globals x)`
  and
  `forall sigma, sigma \in d_ms3a_real_payload_seed x =>
     sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
     sigma.`ms3rp_bits = ms3a_public_bits x /\
     sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x`.

From that package, the skeleton proves two local projection lemmas only:

- **`ms3a_public_payload_bitness_programmed_of_execution_link`** — exact future discharge shape
  for **`A_ms3a_public_payload_bitness_programmed`**.
- **`ms3a_real_seed_public_fields_on_support_of_execution_link`** — exact future discharge shape
  for **`A_ms3a_real_seed_bitness_fields_are_public_on_support`**.

**Import direction check:** this boundary is intentionally acyclic as added.

- `SourceExecutionLink.ec` imports `SourcePayloadDistributions.ec`, `SourceModel.ec`,
  `SourceTypes.ec`, and `BitnessVector.ec` only.
- `SourceProgrammedObligations.ec` can later import `SourceExecutionLink.ec` and replace its two
  remaining axioms with the projection lemmas above.
- `SourcePayloadDistributions.ec` must **not** import `SourceExecutionLink.ec`, or the cycle
  `SourcePayloadDistributions -> SourceExecutionLink -> SourcePayloadDistributions` would be immediate.
- game files do **not** need to import source theorem packaging; they can target
  `ms3a_execution_public_spine_link` directly from a dedicated execution/link theorem.

**Status B (common-lift bridge):** the former broad same-preimage axiom
**`A_ms3a_spine_marginal_pair_common_lift`** was removed and replaced with the narrower
support-level public-fields axiom **`A_ms3a_seed_pair_public_fields_match_on_support`**.
This is a genuine debt reduction: the old witness was stronger than the only downstream
consequence actually consumed in proofs. A preferred “common lift only for already-coupled
pairs” form was **not** adopted because the downstream `ms3a_ax_public_fields` chain quantifies
over **arbitrary** real/sim support pairs, not only pairs already related by a coupling
predicate.

**Programmed-on-support inspection note:** `ms_per_bit_programmed` and
`ms_ordered_challenge_vector_matches` (`BitnessVector.ec`) are the bitness-vector conjuncts.
They apply to **lists carried by seeds** on **`d_ms3a_real_payload_seed`** / **`d_ms3a_sim_payload_seed`** support (real law abstract; sim support is **`supp (dmap (d_ms3a_seed_spine_joint x s) …)`** once the joint is fixed).
`ms3a_public_bits` / `ms3a_public_bitness_globals` and `ms3a_public_bitness_shape_ok` live on the
**public spine** (`SourceModel.ec`). **`A_ms3a_seed_spine_support_wf`** only yields
`ms3a_source_wf` on **spine** draws; it does **not** by itself relate abstract typed seeds to
`ms3a_public_*` — the new projection axioms package that linking explicitly.

### Record fields (current theory)

| Type | Fields |
|------|--------|
| **`ms3a_real_payload_seed`** (= **`ms3a_real_source_payload`**) | `ms3rp_stmt`, `ms3rp_res`, `ms3rp_bits`, `ms3rp_bitness_global_challenges`, `ms3rp_comparison_global_challenge`, `ms3rp_transcript_digest` |
| **`ms3a_sim_payload_seed`** (= **`ms3a_sim_source_payload`**) | `ms3sp_stmt`, `ms3sp_res`, `ms3sp_bits`, `ms3sp_bitness_global_challenges`, `ms3sp_comparison_global_challenge`, `ms3sp_transcript_digest` |
| **`ms3a_bitness_layer_source`** | `ms3s_stmt`, `ms3s_result`, `ms3s_bits`, `ms3s_bitness_global_challenges`, `ms3s_comparison_global_challenge`, `ms3s_transcript_digest` |

**Constructor maps.** `ms3a_bitness_layer_source_of_{real,sim}_payload` copy the six payload
fields into `ms3a_make_{real,sim}_source`, which are **identical** record builders on
`ms3a_bitness_layer_source`. So at the **value** level, real and sim seeds that **agree
on all six fields** map to the **same** bitness-layer source. The EasyCrypt layer still
uses two typed maps (`real` vs `sim`); schedule equality is therefore a statement about
**laws** `d_ms3a_real_payload_seed` / `d_ms3a_sim_payload_seed`, not about distinct
constructors.

**Public-field pairing (pred `ms3a_payload_pair_public_fields_match`).** Matches **four**
fields: statement digest, result bit, comparison-global digest, bitness-global list. It
**does not** mention **`ms3rp_transcript_digest` / `ms3sp_transcript_digest`**; digest
coupling is **orthogonal** to the four `A_ms3a_seed_pair_*_source_shared` lemmas and is
exactly why **public-field pairing alone** cannot replace the spine marginal bridge story for
**`A_ms3a_bitness_layer_seed_schedule`**.

### Proposed concrete seed architecture (high level)

**Option A — Joint / coupling seed (recommended pattern; mirrors MS-3c comparison lane).**

- **Structured joint (in-repo):** `d_ms3a_real_sim_payload_seed_coupling x s` =
  `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer` with
  **`d_ms3a_seed_spine_joint`** abstract on `ms3a_bitness_layer_source` (`SourcePayloadDistributions.ec`)
  and field-copy maps in **`SourceConstructors.ec`**. This is **not** the independent product
  of `d_ms3a_{real,sim}_payload_seed`; MS-3c still uses a product of **concrete** payload laws,
  whereas MS-3a **real** marginal law and the joint remain abstract until games discharge
  **`A_ms3a_spine_real_marginal_matches_seed`** (and related spine obligations:
  `A_ms3a_seed_spine_support_wf`, `A_ms3a_seed_pair_public_fields_match_on_support`); the **sim** marginal
  bridge is **proved** because **`d_ms3a_sim_payload_seed`** is the joint sim marginal **by definition**.
- **Semantic pair predicate** `ms3a_real_sim_payload_seed_coupled` unchanged. On spine
  support, **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`** proves
  **`ms3a_ax_seed_coupling_pair_relation`** from **`forall src \in d_ms3a_seed_spine_joint,
  ms3a_source_wf src`** (programmed bitness vector on the shared spine). Unconditional
  `ms3a_ax_seed_coupling_pair_relation` is **false** in general (spine support can violate WF).
- **Refinement path (alternative to abstract common-lift):** redefine `d_ms3a_{real,sim}_payload_seed` as marginals of a
  correlated joint (or prove a game invariant), then derive the same marginal facts (and optionally replace
  **`A_ms3a_seed_pair_public_fields_match_on_support`**) from **`supp_dprod` / `supp_dmap`** on that joint (MS-3c style).
- In-repo **`A_ms3a_bitness_layer_seed_schedule`** is already a **proved lemma** once the marginal bridge axioms hold:
  rewrite marginals, fold with **`dmap_comp`**, then **`eq_dmap_in`** as in **`SourceScheduleSeed.ec`**
  (pointwise agreement uses the same six-field spine copy as `L_ms3a_real_sim_payload_seed_coupled_layer_maps_eq`).

**Option B — Phase-1 “public spine” + keyed sim noise.**

- Fix a **`op ms3a_public_seed_spine x`** (name illustrative) that samples only the
  fields that games fix from `ms_public_input` / observable surface (statement digest,
  lengths, index lists, …).
- Real law = product of spine + transcript digest law + ROM-derived challenges; sim law =
  same spine + **same** transcript digest + sim challenger randomness in `s`.
- Schedule = proof that both sides collapse to **`dmap` spine `F`** after rewriting
  bitness maps; still needs an explicit **coupling** proof unless spine determines
  `bits` uniquely (it does not — `bits` are rich).

**Option C — Canonical bitness-layer law (single `d_ms3a_bitness_layer_canonical`).**

- Define one distribution on **`ms3a_bitness_layer_source`**, then define each payload
  seed law as a **right-inverse** sampling along `ms3a_bitness_layer_source_of_*` only if
  those maps are made injective / canonicalized — **not** viable without changing the
  structured payload model (many payloads map to the same layer source is not the issue;
  the issue is **underdetermined** inverse). **Low priority** unless the game truly
  samples layer-first.

**Shared public fields (design intent).** The four `source_shared` lemmas package the same
**minimal** joint constraints for constructor lemmas that ignore transcript
digest; proofs currently assume **`A_ms3a_seed_pair_public_fields_match_on_support`** (paired public-field agreement for
arbitrary marginal supports). **Bitness globals** enter through **`ms_ordered_challenge_vector_matches`** on
seed support (programmed axioms) and through pairing.

**Transcript digest.** Must be tied to **`ms_transcript_digest_public_fields`** /
**`ms_transcript_digest_of_observable`** (`TranscriptObservable.ec`) and the abstract
frame (`SourceModel.ec`) when moving from source to **`d_ms3a_bitness_*_observable_v2`**.
Expect **game-level** or **linking** axioms unless digest is defined as a pure function of
the already-committed public fields on support.

**How both push to the “same” bitness-layer source.** For **values** on joint support,
`ms3a_bitness_layer_source_of_real_payload sr` and `ms3a_bitness_layer_source_of_sim_payload
ss` are **equal** when all six fields agree; lemma **`A_ms3a_bitness_layer_seed_schedule`** is the **distributional**
version of that fact, **proved** from spine marginal bridges at the abstract interface.

### Axiom → intended discharge (definitions / lemmas)

| Obligation | Discharge strategy (when seeds are concretized) |
|------------|--------------------------------------------------|
| **`A_ms3a_bitness_layer_seed_schedule`** | **Proved** in `SourceScheduleSeed.ec` from **`A_ms3a_spine_real_marginal_matches_seed`** (axiom) + **`A_ms3a_spine_sim_marginal_matches_seed`** (proved definitional) + **`dmap_comp`** + **`eq_dmap_in`**. |
| **`A_ms3a_spine_sim_marginal_matches_seed`** | **Proved** in `SourcePayloadDistributions.ec` — reflexivity after unfolding **`d_ms3a_sim_payload_seed`**. |
| **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`** | Instantiate **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from games / ROM and prove these facts at the linking layer. |
| **`A_ms3a_real_seed_bits_programmed_on_support`** | **Proved lemma** in `SourceProgrammedObligations.ec` from **`A_ms3a_public_payload_bitness_programmed`** + **`A_ms3a_real_seed_bitness_fields_are_public_on_support`** + `MS_3a_all_bits_from_single_bit`; upstream discharge = prove those **axioms** from execution / ROM + agreement of abstract real seeds with the public spine on support. |
| **`A_ms3a_real_seed_bitness_globals_programmed_on_support`** | **Proved lemma** — same ingredients (`MS_3a_all_bits_from_single_bit` second conjunct). |
| **`A_ms3a_sim_seed_bits_programmed_on_support`** | **Proved lemma** — uses proved **`A_ms3a_sim_seed_bitness_fields_are_public_on_support`**, derived from sim support inversion plus the existing real marginal / real projection bridge. |
| **`A_ms3a_sim_seed_bitness_globals_programmed_on_support`** | **Proved lemma** — same sim projection lemma, then the second conjunct of `MS_3a_all_bits_from_single_bit`. |
| **`A_ms3a_seed_pair_stmt_source_shared`** | **Proved** by projecting **`A_ms3a_seed_pair_public_fields_match_on_support`**. |
| **`A_ms3a_seed_pair_res_source_shared`** | **Proved** — same pattern (`res` field lemma). |
| **`A_ms3a_seed_pair_comparison_global_source_shared`** | **Proved** — comparison-global field lemma. |
| **`A_ms3a_seed_pair_bitness_globals_source_shared`** | **Proved** — bitness-globals field lemma. |

**Already packaged (no seed concretization needed for proof shape).**
`A_ms3a_{real,sim}_seed_programmed_on_support`, `A_ms3a_seed_pair_*_on_support`,
`A_ms3a_seed_pair_public_fields_on_support`, payload support lemmas — these **rewrite**
to seed statements and are done once the execution-seed bridge/package assumptions hold;
the sim projection lemma is already proved, and the former programmed-layer axiom names are now lemmas.

### Blockers (read-only audit)

| Blocker | Why it matters |
|---------|----------------|
| **`ms_public_input`** is an abstract type (`QssmTypes.ec`) | **Mitigation (surface only):** six uninterpreted projections **`ms3a_public_*`** + shape preds **`ms3a_public_{bitness,transcript}_shape_ok`** in **`ms/SourceModel.ec`** mirror the MS-3a seed / v2 field order; **linking** those ops to sampled seeds / games still requires future axioms or definitions (no semantics added yet). |
| **`ms_transcript_observable`** + **`ms3a_observable_of_v2`** abstract | Observable pushforwards (`SourceObservableDistributions.ec`) stay abstract until the v2 ↔ abstract link is constructive beyond **`A_ms3a_observable_of_v2_aligns`**. |
| **`ms_transcript_digest_public_fields`** abstract | Digest cell consistency (`ms_transcript_digest_of_observable`) cannot be proved from source fields alone until digest is a **function** of committed public fields or a game supplies equality. |
| **ROM / FS / `duni_scalar` wiring** | Programmed-bit axioms talk about **`ms_per_bit_programmed`** and challenge splits; concrete seeds must **factor** the same ROM hypotheses used in `BitnessOne` / `FS.ec`. |
| **Game views / witnesses** | Until `G_MS_*` views expose the actual samplers for bitness-after-* and stop using **`msgv_ms_obs = witness`**, the **source** obligations **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_seed_pair_public_fields_match_on_support`** (plus abstract joint / real seed law) and the two execution-seed axioms in `SourceRealExecutionSeed.ec` (`A_ms3a_real_payload_seed_matches_execution_seed`, `A_ms3a_real_execution_seed_link`) remain **linking obligations** relative to `game_pr`. `GameMSHopTypes.ec` and `GameMSHopTransitions.ec` currently package only stage/bound surfaces over frozen `xms` / `s`; they do not define public-input generation, real-seed generation, or transcript/public-field equality. (**`A_ms3a_sim_seed_bitness_fields_are_public_on_support`** is now a proved lemma; the four named `A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support` facts now package the two proved real lemmas together with that sim lemma.) The bitness-layer **seed schedule** is already a **proved lemma** (`A_ms3a_bitness_layer_seed_schedule`) from the real marginal axiom + definitional sim marginal lemma; the four `A_ms3a_seed_pair_*_source_shared` facts are **proved lemmas** by projection from `A_ms3a_seed_pair_public_fields_match_on_support`. |
| **Typed real vs sim payloads** | Lemma **`A_ms3a_bitness_layer_seed_schedule`** is proved from marginal bridges plus `dmap` algebra; EasyCrypt still uses two typed layer maps (`ms3a_bitness_layer_source_of_{real,sim}_payload`), so game-level discharge must still align real/sim samplers with the shared spine story. |

### Public spine projections (`ms/SourceModel.ec`)

| `op` / `pred` | Role |
|----------------|------|
| **`ms3a_public_stmt_digest`**, **`ms3a_public_result_bit`**, **`ms3a_public_bits`**, **`ms3a_public_bitness_globals`**, **`ms3a_public_comparison_global`**, **`ms3a_public_transcript_digest`** | Uninterpreted projections from **`ms_public_input`**, aligned to the six MS-3a seed / v2 fields. |
| **`ms3a_public_bitness_shape_ok`** | `V2_BIT_COUNT` list lengths for bits + bitness globals (`BitnessVector`). |
| **`ms3a_public_transcript_shape_ok`** | **`ms_transcript_digest_of_observable`** on the v2 record built via **`ms3a_pack_observable`** from the six projections (digest cell vs public-field digest). |
| **`ms3a_phase1_real_payload_from_public_input`**, **`ms3a_phase1_sim_payload_from_public_input`** | **`SourceConstructors.ec`** — nominal **`ms3a_{real,sim}_source_payload`** records built from the six **`ms3a_public_*`** fields (same field order; not a single shared return type). |

Abstract **`d_ms3a_real_payload_seed`**, **`d_ms3a_seed_spine_joint`**, **definitional** **`d_ms3a_sim_payload_seed`**, and the one remaining execution/public-spine axiom **`A_ms3a_real_payload_seed_matches_execution_seed`** are the MS-3a proof-interface debt; `ms3a_public_bitness_execution_of_game_execution`, `A_ms3a_public_payload_bitness_programmed`, and `A_ms3a_real_seed_bitness_fields_are_public_on_support` are now all proved lemmas/theorems, and proved lemma **`A_ms3a_sim_seed_bitness_fields_are_public_on_support`** continues to discharge the sim-side projection from the definitional sim marginal plus the existing real bridge. **Narrow source axioms** (**real** marginal bridge, **WF on spine support**, **paired-public support**) live in **`SourcePayloadDistributions.ec`**, and **`A_ms3a_bitness_layer_seed_schedule`** / **`A_ms3a_seed_pair_*_source_shared`** are **proved lemmas** at that interface.

### Smallest **safe** implementation patch (recommended order)

1. **Projection / query ops** — **partially done:** abstract **`ms3a_public_*`** spine + narrow shape preds in **`SourceModel.ec`**, Phase-1 nominal payload constructors **`ms3a_phase1_{real,sim}_payload_from_public_input`** in **`SourceConstructors.ec`**, and the concrete list-level execution constructors **`ms3a_public_bits_of_execution`** / **`ms3a_public_bitness_globals_of_execution`** in **`SourcePublicBitnessConstructors.ec`**. The structural constructor lemmas close, `ms3a_public_bits_per_bit_programmed_of_execution` closes from `ms3a_source_wf`, and `SourceRealExecutionSeed.ec` now proves the concrete theorem that `ms3a_game_public_bitness_source x` satisfies `ms3a_source_wf` and therefore `ms3a_public_bitness_execution_of_game_execution`. Direct definitional rewiring of `SourceModel.ec` is still unnecessary, because no extra globals bridge was needed to close the current proof.
2. **Execution/public-payload linkage** — completed for the current source-side boundary: `SourcePublicBitnessExecution.ec` now centralizes the public-bitness ROM/FS semantics, `SourceRealExecutionGameLink.ec` proves the public-spine corollaries, and `SourceRealExecutionSeed.ec` proves `ms3a_real_execution_seed_link_of_game_execution : forall x, ms3a_real_execution_seed_link x`.
  **Execution-seed package now in use:** `SourceExecutionLink.ec` still names the source-facing
  package as `ms3a_execution_public_spine_link`, while `SourceRealExecutionSeed.ec` now carries the
  concrete boundary law `d_ms3a_real_execution_public_seed x`, the bridge axiom back to
  `d_ms3a_real_payload_seed`, and the proved package theorem `ms3a_real_execution_seed_link_of_game_execution`.
  `SourceProgrammedObligations.ec` already imports that theory and proves the former programmed-layer
  axiom names as lemmas. The recommended next patch is now to replace
  **`A_ms3a_real_payload_seed_matches_execution_seed`** if the exact real-seed law becomes concrete first.
  **Constructor bridge status:** `SourcePublicBitnessConstructors.ec` provided enough local constructor structure for the theorem, and the existing real-seed bridge plus the spine-support axioms were sufficient to close `ms3a_public_bitness_execution_of_game_execution` without adding a globals-equality bridge.
  **Wiring preference:** keep direct definitional
  wiring, because the current file layering keeps `SourceRealExecutionSeed.ec` above
  `SourcePayloadDistributions.ec`. Direct definition becomes the cleaner end-state only after a
  refactor that moves the execution-seed object below the old law.
3. **Joint seed coupling** — **spine phase done:** `d_ms3a_seed_spine_joint` + `dmap` pair
   map give a **real** structured joint; **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`**
   discharges the pair-relation **predicate** from WF on spine support. **Abstract bridges in-repo:**
  marginal equalities / WF / paired-public support are **axioms** in **`SourcePayloadDistributions.ec`**, and
   **`A_ms3a_seed_pair_*_source_shared`** / **`A_ms3a_bitness_layer_seed_schedule`** are **proved lemmas** from them.
   **Still missing at games:** (i) instantiate **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from execution / ROM;
  (ii) **discharge** the **three** remaining source **axioms** (real marginal, WF, paired-public support). The **sim** marginal identity is already **definitional** in EasyCrypt.
3. **Defer** a standalone “canonical **`d_ms3a_bitness_layer_canonical`**” unless the
   execution spec truly samples the layer source first.
4. **Pause MS-3a `.ec` churn** and invest in **game / LE** linking **only if** the team
   needs `game_pr` facts before choosing joint laws — the joint law should be **read
   off** the real/sim game samplers, not invented in isolation.

### README pointer

See **this section** under **Seed distribution concretization** for the authoritative
audit; the README MS bullet stays a short summary.

## MS-3a hardening (completed in this phase; not MS-3b)

- Replaced the polymorphic **`dmap_source_constructor_in_image`** axiom with **`supp_dmap`** (`Distr`) and a small proved **`distr_mem_eq`** helper; mem-pair / WF lemmas use `case/supp_dmap` and preserved membership hypotheses where proof terms require terms, not bare formulas.
- Split the old “one-shot” source equality story: lemma **`A_ms3a_bitness_layer_seed_schedule`** (single `dmap` per side at the abstract seed through the layer maps) is **proved** from **`A_ms3a_spine_real_marginal_matches_seed`** (axiom) + **`A_ms3a_spine_sim_marginal_matches_seed`** (**proved** definitional) + **`dmap_comp`** + **`eq_dmap_in`**; legacy **`from_seed`** composition is **proved** redundant via **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`**. Lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`** is the former payload-level statement, now **proved** from **`A_ms3a_bitness_layer_seed_schedule`** + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`dmap_comp`** (`ms3a_bitness_*_source_as_seed_dmap`). The former `ms3a_ax_*` premises are **proved lemmas** unpacking support from the three **payload-support lemmas**, which in turn follow from **seed-support** (real/sim programmed lemmas each from two programmed-field **lemmas** + four paired-public **`source_shared` lemmas** + lemmata `A_ms3a_seed_pair_*_on_support`, `A_ms3a_seed_pair_public_fields_on_support`) and the defining payload `dmap`s; **`ms3a_payload_schedule_equivalence`** is **deprecated / compatibility** packaging (ignores those hypotheses). **`ms3a_source_eq_from_bitness_layer`** unfolds folded `d_ms3a_bitness_*_source` and applies **`A_ms3a_payload_dmap_bitness_layer_schedule`**.
- **Constructor obligations** formerly axiomatized at the folded-source layer are now **proved lemmas**: WF and programmed-bitness use payload support lemmas; public-field agreement uses `ms3a_payload_pair_public_fields_on_support` and **`ms3a_real_sim_public_fields_of_payload_pair`**; per-index exact simulation rewrites the programmed-vector hypothesis with the `dmap` preimage equality (`-Heqr`) and calls **`MS_3a_bitness_layer_exact_simulation`**. **forall** intros on paired real/sim binders use the quantifier order `(stmt_r stmt_s …)` (not “all real then all sim”) so constructor arguments type-check.

## Next target

**MS-3a coupling (immediate):** instantiate **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from execution
  (and discharge **`A_ms3a_seed_spine_support_wf`** / **`A_ms3a_seed_pair_public_fields_match_on_support`** as needed), then **prove** **`A_ms3a_spine_real_marginal_matches_seed`** tying the joint’s real marginal to **`d_ms3a_real_payload_seed`**. The **sim** marginal identity is already **definitional** (`d_ms3a_sim_payload_seed` + lemma **`A_ms3a_spine_sim_marginal_matches_seed`**). The four **`A_ms3a_seed_pair_*_source_shared`** lemmas and
   **`A_ms3a_bitness_layer_seed_schedule`** are already **proved** in `ms/source/` from those obligations.

**MS-3a residual:** discharge the **three** spine **axioms** in **`SourcePayloadDistributions.ec`** at games, plus the **three** programmed-layer **axioms** in **`SourceProgrammedObligations.ec`** (public vector programmed + real/sim seed fields agree with public spine on abstract support; the four `A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support` statements are **proved lemmas**); instantiate abstract **`d_ms3a_real_payload_seed`** / **`d_ms3a_seed_spine_joint`** from the execution spec / games (**`d_ms3a_sim_payload_seed`** is already the joint sim marginal **by definition**; `ms3a_*_payload_from_seed` is definitional identity on payload-shaped seeds; **`A_ms3a_seed_pair_public_fields_on_support`** is already a **proved lemma**). Optionally **`ms3a_pack_observable_with_digest_field_correct`** and **`duni_scalar_shift_reparam`**.

**MS-3b** (`MS_3b_true_clause_characterization`) is the **recommended next milestone** once the remaining MS-3a axiom surface above is acceptable: folded-source constructor lemmas are no longer axioms, and folded real/sim source equality is proved via **`A_ms3a_payload_dmap_bitness_layer_schedule`** (from lemma **`A_ms3a_bitness_layer_seed_schedule`** + `dmap_comp`; the five `ms3a_ax_*` predicates are separate proved lemmas, not schedule premises).
