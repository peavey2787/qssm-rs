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
| `d_ms3a_real_payload_seed` | **Abstract** (`ms/source/SourcePayloadDistributions.ec`; re-exported **`SourceDistributions`**) — primary **real** sampling obligation to instantiate from execution/games |
| `d_ms3a_sim_payload_seed` | **Defined** as `dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer` (same file); **`A_ms3a_spine_sim_marginal_matches_seed`** is a **proved** definitional lemma |
| `d_ms3a_seed_spine_joint` | **Abstract spine law** (`ms/source/SourcePayloadDistributions.ec`) — one `ms3a_bitness_layer_source` draw per `(x,s)`; joint typed seeds are definitional copies (`SourceConstructors.ec`) |
| `d_ms3a_real_sim_payload_seed_coupling`, `d_ms3a_coupling_seed_{real,sim}_projection`, `ms3a_real_sim_payload_seed_coupled`, `ms3a_ax_seed_coupling_pair_relation`, `ms3a_ax_seed_support_coupling` | **Definitions** (`ms/source/SourceCouplingTypes.ec`) — joint = `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer` (shared spine, **not** the independent product of abstract **`d_ms3a_real_payload_seed`** with an unrelated sim law — here **`d_ms3a_sim_payload_seed`** is the joint sim marginal **by definition**); pair predicate as before; **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`** proves `ms3a_ax_seed_coupling_pair_relation` from `ms3a_source_wf` on spine support (`SourceCouplingTheorem.ec`); projections fold to `dmap` off the spine (`L_ms3a_coupling_seed_{real,sim}_projection_dmap_spine`); spine obligations in **`SourcePayloadDistributions.ec`**: **axioms** **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_spine_marginal_pair_common_lift`**, plus **proved lemma** **`A_ms3a_spine_sim_marginal_matches_seed`** (sim seed law is the joint sim marginal **by definition**; **`SourceCouplingAxioms.ec`** summarizes packaging) |
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
| `A_ms3a_public_payload_bitness_programmed` | **Axiom** (`SourceProgrammedObligations.ec`) — `ms_bitness_vector_programmed_layer` on the public spine (`ms3a_public_stmt_digest`, `ms3a_public_bits`, `ms3a_public_bitness_globals`); ROM / FS / transcript programming surface |
| `A_ms3a_real_seed_bitness_fields_are_public_on_support` | **Axiom** (`SourceProgrammedObligations.ec`) — every real seed on abstract support **equals** the public spine on stmt / bits / bitness globals |
| `A_ms3a_sim_seed_bitness_fields_are_public_on_support` | **Axiom** (`SourceProgrammedObligations.ec`) — same for sim seeds (keyed by `s`) |
| `A_ms3a_real_seed_bits_programmed_on_support`, `A_ms3a_real_seed_bitness_globals_programmed_on_support` | **Proved lemmas** (`SourceProgrammedObligations.ec`) — from the three axioms above + `MS_3a_all_bits_from_single_bit` (`BitnessVector.ec`) |
| `A_ms3a_real_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — from the two real **lemmas** above + unfolds |
| `ms3a_sim_payload_programmed_layer_as_bitness_vector` | **Proved** (`SourceConstructors.ec`) — `ms3a_sim_payload_programmed_layer p` iff `ms_bitness_vector_programmed_layer` on `p.`ms3sp_stmt / bits / bitness globals |
| `A_ms3a_sim_seed_bits_programmed_on_support`, `A_ms3a_sim_seed_bitness_globals_programmed_on_support` | **Proved lemmas** (`SourceProgrammedObligations.ec`) — sim analogue of the two real **lemmas** above |
| `A_ms3a_sim_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — from the two sim **lemmas** above + unfolds |
| `ms3a_payload_pair_stmt_eq_from_seed_of_seed_stmt_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` statement field equals seed `ms3rp_stmt` / `ms3sp_stmt` when those agree |
| `ms3a_payload_pair_res_eq_from_seed_of_seed_res_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` result field equals seed `ms3rp_res` / `ms3sp_res` when those agree |
| `ms3a_payload_pair_comparison_global_challenge_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` comparison-global digest equals seed fields when those agree |
| `ms3a_payload_pair_bitness_global_challenges_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` bitness-global lists equal seed fields when those agree |
| `L_ms3a_seed_pair_{stmt,res,comparison_global,bitness_globals}_when_seeds_are_phase1` | **Proved** (`SourcePublicFieldObligations.ec`) — same four conclusions as **`A_ms3a_seed_pair_*_source_shared`** when joint-support seeds **are** the Phase-1 spine records (membership hypotheses unused in proof) |
| `A_ms3a_seed_pair_stmt_source_shared` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — from **`A_ms3a_spine_marginal_pair_common_lift`** + **`L_ms3a_payload_pair_stmt_seed_of_bitness`** (`SourceConstructors.ec`) |
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
| Spine real marginal + WF + same-spine lift | **Axioms** `A_ms3a_spine_real_marginal_matches_seed`, `A_ms3a_seed_spine_support_wf`, `A_ms3a_spine_marginal_pair_common_lift` (`ms/source/SourcePayloadDistributions.ec`) — game-level discharge once `d_ms3a_seed_spine_joint` / `d_ms3a_real_payload_seed` are instantiated |
| Spine sim marginal | **Lemma** `A_ms3a_spine_sim_marginal_matches_seed` — **proved** (definitional): `d_ms3a_sim_payload_seed` is `dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer` |
| Seed-level bitness-layer schedule (single `dmap` per side off abstract seeds) | **Lemma** `A_ms3a_bitness_layer_seed_schedule` (`ms/source/SourceScheduleSeed.ec`) — **proved** equality `dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload = dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload` from **`A_ms3a_spine_real_marginal_matches_seed`** + **`A_ms3a_spine_sim_marginal_matches_seed`** + **`Distr.dmap_comp`** + **`eq_dmap_in`** (see “Schedule (seed boundary)” below). **Proved packaging:** `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap` (`SourceBitnessDistributions.ec`) and `L_ms3a_bitness_layer_seed_schedule_composed_form` (`SourceScheduleSeed.ec`) recover the legacy **`… \o ms3a_*_payload_from_seed`** statement |
| Payload-level `dmap` schedule (nested payload pushforwards) | **Lemma** `A_ms3a_payload_dmap_bitness_layer_schedule` (`SourceSchedulePayload.ec`) — **proved** from `A_ms3a_bitness_layer_seed_schedule` + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`ms3a_bitness_{real,sim}_source_as_seed_dmap`**. **`ms3a_payload_schedule_equivalence`** — **deprecated / compatibility wrapper** (proved; redundant `ms3a_ax_*` hypotheses unused in proof). **`ms3a_source_eq_from_bitness_layer`** — **proved** in `SourceScheduleTheorem.ec` without those hypotheses |
| `ms3a_ax_real_wf`, `ms3a_ax_sim_wf`, `ms3a_ax_public_fields`, `ms3a_ax_prog_layer`, `ms3a_ax_bitness_exact` | **Proved lemmas** from payload-support lemmas + `dmap`/`supp_dmap` (`SourceSchedulePayload.ec`; facade `SourceScheduleObligations.ec`); **`ms3a_ax_*_from_axioms`** in `SourceTheorem.ec` |
| Seed support (programmed layer on **seed** support) | **Lemmas** `A_ms3a_real_seed_programmed_on_support`, `A_ms3a_sim_seed_programmed_on_support` from four proved **lemmas** (`A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support`; `ms/source/SourceProgrammedObligations.ec`), each proved from three **axioms** (`A_ms3a_public_payload_bitness_programmed`, `A_ms3a_real_seed_bitness_fields_are_public_on_support`, `A_ms3a_sim_seed_bitness_fields_are_public_on_support`) |
| Seed support (paired **public** fields on joint seed support) | **Proved lemmas** `A_ms3a_seed_pair_stmt_source_shared`, `A_ms3a_seed_pair_res_source_shared`, `A_ms3a_seed_pair_comparison_global_source_shared`, `A_ms3a_seed_pair_bitness_globals_source_shared` (`ms/source/SourcePublicFieldObligations.ec`) from **`A_ms3a_spine_marginal_pair_common_lift`** + field-copy lemmas; **lemmata** `A_ms3a_seed_pair_stmt_on_support`, …, `A_ms3a_seed_pair_bitness_globals_on_support`; **lemma** `A_ms3a_seed_pair_public_fields_on_support` combines into `ms3a_payload_pair_public_fields_match` for `from_seed` |
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
4. **Common bitness-layer image** — the **equality** of the two seed pushforwards (layer maps off abstract seeds) is lemma **`A_ms3a_bitness_layer_seed_schedule`**, **proved** from **`A_ms3a_spine_real_marginal_matches_seed`** + **`A_ms3a_spine_sim_marginal_matches_seed`** (the latter **proved** definitional) plus `dmap` algebra (still a **proof obligation** at game level to discharge the **real** marginal axiom and the WF / common-lift axioms).
5. **Public-field alignment** — **`A_ms3a_seed_pair_*_source_shared`** are **proved lemmas** from **`A_ms3a_spine_marginal_pair_common_lift`** (they still do **not** imply the schedule alone: they omit **`ms3rp_transcript_digest` / `ms3sp_transcript_digest`**, so transcript-digest coupling is **not** captured by the four paired-public facts alone).

**Tradeoff:** the schedule statement remains **unconditional** on `ms3a_ax_*` (those five predicates stay **proved lemmas**
from payload-support lemmas (from programmed seed axioms + `source_shared` lemmas), not schedule side-conditions).

**`ms3a_payload_schedule_equivalence`:** treat as **legacy / wrapper** packaging
only. New proofs should cite **`A_ms3a_bitness_layer_seed_schedule`**, lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`**, or **`ms3a_source_eq_from_bitness_layer`**; do not read the five `ms3a_payload_schedule_equivalence` hypotheses as part of the schedule proof obligation.

## Seed distribution concretization (design audit)

This section records **what must become concrete** so abstract
`d_ms3a_real_payload_seed` and the spine joint can eventually discharge the remaining MS-3a
**axioms** (three public-spine / projection facts for programmed-on-support, three spine axioms — real marginal / WF / common-lift — plus abstract joint), without editing `.ec` proofs here. (**`d_ms3a_sim_payload_seed`** is now **defined** from the joint; the old sim marginal axiom is a **proved** lemma.)

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
joint’s real marginal for every **`s`**), **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_spine_marginal_pair_common_lift`**.

**Why `A_ms3a_spine_marginal_pair_common_lift` stays an axiom:** it is a **same-preimage** obligation
for arbitrary pairs on the **marginal** supports — strictly stronger than marginal **law**
equalities alone (product-of-supports can exceed coupled joint support). The four
**`A_ms3a_seed_pair_*_source_shared`** proofs still require a **single** spine witness for each pair
`(sr, ss)`.

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
  `A_ms3a_seed_spine_support_wf`, `A_ms3a_spine_marginal_pair_common_lift`); the **sim** marginal
  bridge is **proved** because **`d_ms3a_sim_payload_seed`** is the joint sim marginal **by definition**.
- **Semantic pair predicate** `ms3a_real_sim_payload_seed_coupled` unchanged. On spine
  support, **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`** proves
  **`ms3a_ax_seed_coupling_pair_relation`** from **`forall src \in d_ms3a_seed_spine_joint,
  ms3a_source_wf src`** (programmed bitness vector on the shared spine). Unconditional
  `ms3a_ax_seed_coupling_pair_relation` is **false** in general (spine support can violate WF).
- **Refinement path (alternative to abstract common-lift):** redefine `d_ms3a_{real,sim}_payload_seed` as marginals of a
  correlated joint (or prove a game invariant), then derive the same marginal facts (and optionally replace
  **`A_ms3a_spine_marginal_pair_common_lift`**) from **`supp_dprod` / `supp_dmap`** on that joint (MS-3c style).
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
digest; proofs currently assume **`A_ms3a_spine_marginal_pair_common_lift`** (same spine preimage for
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
| **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_spine_marginal_pair_common_lift`** | Instantiate **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from games / ROM and prove these facts at the linking layer. |
| **`A_ms3a_real_seed_bits_programmed_on_support`** | **Proved lemma** in `SourceProgrammedObligations.ec` from **`A_ms3a_public_payload_bitness_programmed`** + **`A_ms3a_real_seed_bitness_fields_are_public_on_support`** + `MS_3a_all_bits_from_single_bit`; upstream discharge = prove those **axioms** from execution / ROM + agreement of abstract real seeds with the public spine on support. |
| **`A_ms3a_real_seed_bitness_globals_programmed_on_support`** | **Proved lemma** — same ingredients (`MS_3a_all_bits_from_single_bit` second conjunct). |
| **`A_ms3a_sim_seed_bits_programmed_on_support`** | **Proved lemma** — uses **`A_ms3a_sim_seed_bitness_fields_are_public_on_support`** instead of the real projection axiom. |
| **`A_ms3a_sim_seed_bitness_globals_programmed_on_support`** | **Proved lemma** — sim analogue of globals lemma. |
| **`A_ms3a_seed_pair_stmt_source_shared`** | **Proved** from **`A_ms3a_spine_marginal_pair_common_lift`** + **`L_ms3a_payload_pair_stmt_seed_of_bitness`**. |
| **`A_ms3a_seed_pair_res_source_shared`** | **Proved** — same pattern (`res` field lemma). |
| **`A_ms3a_seed_pair_comparison_global_source_shared`** | **Proved** — comparison-global field lemma. |
| **`A_ms3a_seed_pair_bitness_globals_source_shared`** | **Proved** — bitness-globals field lemma. |

**Already packaged (no seed concretization needed for proof shape).**
`A_ms3a_{real,sim}_seed_programmed_on_support`, `A_ms3a_seed_pair_*_on_support`,
`A_ms3a_seed_pair_public_fields_on_support`, payload support lemmas — these **rewrite**
to seed statements and are done once the three programmed-layer **axioms** (and hence the four field **lemmas**) hold.

### Blockers (read-only audit)

| Blocker | Why it matters |
|---------|----------------|
| **`ms_public_input`** is an abstract type (`QssmTypes.ec`) | **Mitigation (surface only):** six uninterpreted projections **`ms3a_public_*`** + shape preds **`ms3a_public_{bitness,transcript}_shape_ok`** in **`ms/SourceModel.ec`** mirror the MS-3a seed / v2 field order; **linking** those ops to sampled seeds / games still requires future axioms or definitions (no semantics added yet). |
| **`ms_transcript_observable`** + **`ms3a_observable_of_v2`** abstract | Observable pushforwards (`SourceObservableDistributions.ec`) stay abstract until the v2 ↔ abstract link is constructive beyond **`A_ms3a_observable_of_v2_aligns`**. |
| **`ms_transcript_digest_public_fields`** abstract | Digest cell consistency (`ms_transcript_digest_of_observable`) cannot be proved from source fields alone until digest is a **function** of committed public fields or a game supplies equality. |
| **ROM / FS / `duni_scalar` wiring** | Programmed-bit axioms talk about **`ms_per_bit_programmed`** and challenge splits; concrete seeds must **factor** the same ROM hypotheses used in `BitnessOne` / `FS.ec`. |
| **Game views / witnesses** | Until `G_MS_*` views expose the actual samplers for bitness-after-*, the **spine** obligations **`A_ms3a_spine_real_marginal_matches_seed`**, **`A_ms3a_seed_spine_support_wf`**, **`A_ms3a_spine_marginal_pair_common_lift`** (plus abstract joint / real seed law) and the **three** public-spine / seed-projection axioms in `SourceProgrammedObligations.ec` remain **linking obligations** relative to `game_pr`. (The four named `A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support` facts are **proved lemmas** from those three axioms.) The bitness-layer **seed schedule** is already a **proved lemma** (`A_ms3a_bitness_layer_seed_schedule`) from the real marginal axiom + definitional sim marginal lemma; the four `A_ms3a_seed_pair_*_source_shared` facts are **proved lemmas** from `A_ms3a_spine_marginal_pair_common_lift`. |
| **Typed real vs sim payloads** | Lemma **`A_ms3a_bitness_layer_seed_schedule`** is proved from marginal bridges plus `dmap` algebra; EasyCrypt still uses two typed layer maps (`ms3a_bitness_layer_source_of_{real,sim}_payload`), so game-level discharge must still align real/sim samplers with the shared spine story. |

### Public spine projections (`ms/SourceModel.ec`)

| `op` / `pred` | Role |
|----------------|------|
| **`ms3a_public_stmt_digest`**, **`ms3a_public_result_bit`**, **`ms3a_public_bits`**, **`ms3a_public_bitness_globals`**, **`ms3a_public_comparison_global`**, **`ms3a_public_transcript_digest`** | Uninterpreted projections from **`ms_public_input`**, aligned to the six MS-3a seed / v2 fields. |
| **`ms3a_public_bitness_shape_ok`** | `V2_BIT_COUNT` list lengths for bits + bitness globals (`BitnessVector`). |
| **`ms3a_public_transcript_shape_ok`** | **`ms_transcript_digest_of_observable`** on the v2 record built via **`ms3a_pack_observable`** from the six projections (digest cell vs public-field digest). |
| **`ms3a_phase1_real_payload_from_public_input`**, **`ms3a_phase1_sim_payload_from_public_input`** | **`SourceConstructors.ec`** — nominal **`ms3a_{real,sim}_source_payload`** records built from the six **`ms3a_public_*`** fields (same field order; not a single shared return type). |

Abstract **`d_ms3a_real_payload_seed`**, **`d_ms3a_seed_spine_joint`**, **definitional** **`d_ms3a_sim_payload_seed`**, and the **three** programmed-layer **axioms** (`A_ms3a_public_payload_bitness_programmed`, `A_ms3a_real_seed_bitness_fields_are_public_on_support`, `A_ms3a_sim_seed_bitness_fields_are_public_on_support`) are unchanged at the proof interface; **narrow spine axioms** (**real** marginal bridge, **WF on spine support**, **common-lift**) live in **`SourcePayloadDistributions.ec`**, and **`A_ms3a_bitness_layer_seed_schedule`** / **`A_ms3a_seed_pair_*_source_shared`** are **proved lemmas** at that interface.

### Smallest **safe** implementation patch (recommended order)

1. **Projection / query ops** — **partially done:** abstract **`ms3a_public_*`** spine + narrow shape preds in **`SourceModel.ec`**, plus Phase-1 nominal payload constructors **`ms3a_phase1_{real,sim}_payload_from_public_input`** in **`SourceConstructors.ec`**. Next: link projections (and/or payloads) to games/spec **without** guessed sampling. This unlocks Phase-1-style **length and index** reasoning (as in MS-3c) once equalities are assumed or proved.
2. **Joint seed coupling** — **spine phase done:** `d_ms3a_seed_spine_joint` + `dmap` pair
   map give a **real** structured joint; **`L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf`**
   discharges the pair-relation **predicate** from WF on spine support. **Abstract bridges in-repo:**
   marginal equalities / WF / common-lift are **axioms** in **`SourcePayloadDistributions.ec`**, and
   **`A_ms3a_seed_pair_*_source_shared`** / **`A_ms3a_bitness_layer_seed_schedule`** are **proved lemmas** from them.
   **Still missing at games:** (i) instantiate **`d_ms3a_seed_spine_joint`** / **`d_ms3a_real_payload_seed`** from execution / ROM;
   (ii) **discharge** the **three** remaining spine **axioms** (real marginal, WF, common-lift). The **sim** marginal identity is already **definitional** in EasyCrypt.
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
   (and discharge **`A_ms3a_seed_spine_support_wf`** / **`A_ms3a_spine_marginal_pair_common_lift`** as needed), then **prove** **`A_ms3a_spine_real_marginal_matches_seed`** tying the joint’s real marginal to **`d_ms3a_real_payload_seed`**. The **sim** marginal identity is already **definitional** (`d_ms3a_sim_payload_seed` + lemma **`A_ms3a_spine_sim_marginal_matches_seed`**). The four **`A_ms3a_seed_pair_*_source_shared`** lemmas and
   **`A_ms3a_bitness_layer_seed_schedule`** are already **proved** in `ms/source/` from those obligations.

**MS-3a residual:** discharge the **three** spine **axioms** in **`SourcePayloadDistributions.ec`** at games, plus the **three** programmed-layer **axioms** in **`SourceProgrammedObligations.ec`** (public vector programmed + real/sim seed fields agree with public spine on abstract support; the four `A_ms3a_{real,sim}_seed_{bits,bitness_globals}_programmed_on_support` statements are **proved lemmas**); instantiate abstract **`d_ms3a_real_payload_seed`** / **`d_ms3a_seed_spine_joint`** from the execution spec / games (**`d_ms3a_sim_payload_seed`** is already the joint sim marginal **by definition**; `ms3a_*_payload_from_seed` is definitional identity on payload-shaped seeds; **`A_ms3a_seed_pair_public_fields_on_support`** is already a **proved lemma**). Optionally **`ms3a_pack_observable_with_digest_field_correct`** and **`duni_scalar_shift_reparam`**.

**MS-3b** (`MS_3b_true_clause_characterization`) is the **recommended next milestone** once the remaining MS-3a axiom surface above is acceptable: folded-source constructor lemmas are no longer axioms, and folded real/sim source equality is proved via **`A_ms3a_payload_dmap_bitness_layer_schedule`** (from lemma **`A_ms3a_bitness_layer_seed_schedule`** + `dmap_comp`; the five `ms3a_ax_*` predicates are separate proved lemmas, not schedule premises).
