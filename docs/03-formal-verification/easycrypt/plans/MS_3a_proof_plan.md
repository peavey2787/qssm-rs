# MS-3a Proof Plan (EasyCrypt)

This note is **design + formal target tracking** for MS-3a. **`MS_3a_exact_bitness_simulation` is not vacuous**: it proves the predicate **`ms3a_bitness_real_sim_equiv`** (equality of abstract `ms_transcript_observable` distributions) via the layered lemma **`MS_3a_exact_bitness_simulation_from_layers`**. The skeleton admit is now discharged via a named packaging bridge lemma; remaining open obligations are listed in the checklist.

**`ms/source/` obligations layout:** lemmas and axioms are split across **`SourceProgrammedObligations.ec`** (programmed-on-support seed layer), **`SourcePublicFieldObligations.ec`** (paired public fields and payload-support public bridges), and **`SourceScheduleObligations.ec`** (bitness-layer schedule, `ms3a_ax_*` from support, constructor-scoped lemmas). **`SourceObligations.ec`** re-exports them; **`require import SourceObligations`** is unchanged.

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

**Source packaging (`ms/source/SourceTypes.ec`, `SourceConstructors.ec`, `SourceDistributions.ec` facade over `SourcePayloadDistributions` / `SourceBitnessDistributions` / `SourceDistributionLemmas` / `SourceObservableDistributions`):** `ms3a_real_source_payload` / `ms3a_sim_source_payload` are record types whose fields match the arguments to `ms3a_make_real_source` / `ms3a_make_sim_source`. **Seed** types `ms3a_real_payload_seed` / `ms3a_sim_payload_seed` are **aliases** of those payload records (same field surface: stmt, result, bits, bitness global challenges, comparison global challenge, transcript digest). **`ms3a_real_payload_from_seed`** / **`ms3a_sim_payload_from_seed`** are the **identity** on that shared type (parameters `x` / `s` reserved for keyed sampling from execution). Laws **`d_ms3a_real_source_payload`** / **`d_ms3a_sim_source_payload`** are **by definition** `dmap` pushforwards of abstract **`d_ms3a_{real,sim}_payload_seed`** through those maps. Laws `d_ms3a_bitness_real_source` / `d_ms3a_bitness_sim_source` remain **by definition** `dmap` of payload laws through `ms3a_bitness_layer_source_of_{real,sim}_payload`.

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
| `d_ms3a_real_payload_seed`, `d_ms3a_sim_payload_seed` | **Abstract seed distrs** (`ms/source/SourcePayloadDistributions.ec`; re-exported **`SourceDistributions`**) — primary sampling obligations to instantiate from execution/games |
| `d_ms3a_real_source_payload`, `d_ms3a_sim_source_payload` | **Defined** (`ms/source/SourcePayloadDistributions.ec`) as `dmap` pushforwards of seed laws through `ms3a_{real,sim}_payload_from_seed` (`SourceConstructors.ec`) |
| `d_ms3a_bitness_real_source`, `d_ms3a_bitness_sim_source` | **Defined** (`ms/source/SourceBitnessDistributions.ec`) as `dmap` pushforwards of payload laws through `ms3a_bitness_layer_source_of_{real,sim}_payload` (wrappers over `ms3a_make_*_source`) |
| `dmap` preimage / membership for `d_ms3a_bitness_*_source` | **Proved** — `case/supp_dmap` on `Distr.supp_dmap` plus local `distr_mem_eq` (`ms/source/SourceDistributionLemmas.ec`; **MS-3a hardening**, not MS-3b) |
| `ms3a_public_stmt_digest`, `ms3a_public_result_bit`, `ms3a_public_bits`, `ms3a_public_bitness_globals`, `ms3a_public_comparison_global`, `ms3a_public_transcript_digest` | **Abstract ops** (`ms/SourceModel.ec`) — six-field spine from **`ms_public_input`** (no axioms; linking deferred) |
| `ms3a_public_bitness_shape_ok`, `ms3a_public_transcript_shape_ok` | **Defined preds** (`ms/SourceModel.ec`) — `V2_BIT_COUNT` lengths + **`ms_transcript_digest_of_observable`** on packed spine |
| `ms3a_pack_observable` | **Defined** (`ms/SourceModel.ec`) — canonical v2 packer |
| `d_ms3a_bitness_*_observable_v2`, `d_ms3a_bitness_*_observable`, `ms3a_bitness_real_sim_equiv` (pred), `ms3a_source_observable_equiv_from_layer` | **Defined / proved** (`ms/source/SourceObservableDistributions.ec`) — `dmap` / `dlet` from structured source and abstract pushforward |
| `ms3a_bitness_real_source_as_seed_dmap`, `ms3a_bitness_sim_source_as_seed_dmap` | **Proved** (`SourceBitnessDistributions.ec`) — fold nested payload `dmap`s to a **single** `dmap` off `d_ms3a_{real,sim}_payload_seed` using **`Distr.dmap_comp`** |
| `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`, `L_ms3a_bitness_layer_seed_schedule_composed_form` | **Proved** — `from_seed` is definitional identity, so composed seed maps coincide with **`ms3a_bitness_layer_source_of_{real,sim}_payload`** alone (`SourceBitnessDistributions` / `SourceScheduleObligations`) |
| `ms3a_frame_consistent`, `ms3a_packed_frame` | **Predicates** (`ms/SourceModel.ec`) — reusable frame consistency + packed-field constructor relation |
| `MS_3a_frame_consistent_of_v2` | **Proved** (`ms/SourceModel.ec`) — derives alignment+digest frame from `ms_transcript_digest_of_observable` using `A_ms3a_observable_of_v2_aligns` |
| `MS_3a_exact_bitness_simulation_from_layers` | **Proved** (`ms/source/SourceTheorem.ec`) — reduced to `ms3a_source_observable_equiv_from_layer` using named source-equality premise |
| `MS_3a_exact_bitness_simulation` | **Lemma** (`ms/source/SourceTheorem.ec`) — wrapper now uses named obligations `ms3a_default_source_eq` and `ms3a_default_frame_consistent` (no anonymous admit) |
| `ms3a_real_payload_from_seed_def`, `ms3a_sim_payload_from_seed_def` | **Proved** (`SourceConstructors.ec`) — identity packaging for seed→payload |
| `ms3a_real_payload_programmed_layer_as_bitness_vector` | **Proved** (`SourceConstructors.ec`) — `ms3a_real_payload_programmed_layer p` iff `ms_bitness_vector_programmed_layer` on `p.`ms3rp_stmt / bits / bitness globals |
| `A_ms3a_real_seed_bits_programmed_on_support`, `A_ms3a_real_seed_bitness_globals_programmed_on_support` | **Axioms** (`SourceProgrammedObligations.ec`) — real seed support: `ms_per_bit_programmed` and `ms_ordered_challenge_vector_matches` (`BitnessVector.ec`), the two conjuncts of `ms_bitness_vector_programmed_layer` |
| `A_ms3a_real_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — former real programmed-on-support axiom, from the two axioms above + unfolds |
| `ms3a_sim_payload_programmed_layer_as_bitness_vector` | **Proved** (`SourceConstructors.ec`) — `ms3a_sim_payload_programmed_layer p` iff `ms_bitness_vector_programmed_layer` on `p.`ms3sp_stmt / bits / bitness globals |
| `A_ms3a_sim_seed_bits_programmed_on_support`, `A_ms3a_sim_seed_bitness_globals_programmed_on_support` | **Axioms** (`SourceProgrammedObligations.ec`) — sim seed support (keyed by `s`): same two conjuncts as real |
| `A_ms3a_sim_seed_programmed_on_support` | **Proved lemma** (`SourceProgrammedObligations.ec`) — former sim programmed-on-support axiom, from the two sim axioms above + unfolds |
| `ms3a_payload_pair_stmt_eq_from_seed_of_seed_stmt_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` statement field equals seed `ms3rp_stmt` / `ms3sp_stmt` when those agree |
| `ms3a_payload_pair_res_eq_from_seed_of_seed_res_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` result field equals seed `ms3rp_res` / `ms3sp_res` when those agree |
| `ms3a_payload_pair_comparison_global_challenge_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` comparison-global digest equals seed fields when those agree |
| `ms3a_payload_pair_bitness_global_challenges_eq_from_seed_of_seed_eq` | **Proved** (`SourceConstructors.ec`) — `from_seed` bitness-global lists equal seed fields when those agree |
| `A_ms3a_seed_pair_stmt_source_shared` | **Axiom** (`SourcePublicFieldObligations.ec`) — joint seed support: real/sim seed **record** statement digests agree (shared public statement source at sampling) |
| `A_ms3a_seed_pair_stmt_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` stmt equality, from `A_ms3a_seed_pair_stmt_source_shared` + identity |
| `A_ms3a_seed_pair_res_source_shared` | **Axiom** (`SourcePublicFieldObligations.ec`) — joint seed support: real/sim seed **record** result bits agree |
| `A_ms3a_seed_pair_res_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` res equality, from `A_ms3a_seed_pair_res_source_shared` + identity |
| `A_ms3a_seed_pair_comparison_global_source_shared` | **Axiom** (`SourcePublicFieldObligations.ec`) — joint seed support: real/sim seed **record** comparison-global digests agree |
| `A_ms3a_seed_pair_comparison_global_on_support` | **Proved lemma** (`SourcePublicFieldObligations.ec`) — payload `from_seed` comparison-global equality, from source-shared + identity |
| `A_ms3a_seed_pair_bitness_globals_source_shared` | **Axiom** (`SourcePublicFieldObligations.ec`) — joint seed support: real/sim seed **record** bitness-global challenge lists agree |
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
- **`MS_3a_exact_bitness_simulation`** — applies the skeleton with concrete lemma proof terms; `ms3a_default_source_eq` is now **proved** by **`ms3a_source_eq_from_bitness_layer`**, which unfolds folded `d_ms3a_bitness_*_source` to payload `dmap`s and applies lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`** (proved from axiom **`A_ms3a_bitness_layer_seed_schedule`** + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`ms3a_bitness_{real,sim}_source_as_seed_dmap`**; no `ms3a_ax_*` premises). The five `ms3a_ax_*` predicates are still used by mem-pair lemmas and are **proved lemmas** (`ms3a_ax_*_from_payload_support` / `*_from_real_sim_wf` in `SourceScheduleObligations.ec`, packaged as `ms3a_ax_*_from_axioms` in `SourceTheorem.ec`) **derived from** the three **payload-support lemmas** alone; those payload-support lemmas are in turn **proved** from the **seed-level axioms** (not added as parallel hypotheses). Concretely: **`ms3a_payload_{real,sim}_support_programmed`** use **`A_ms3a_{real,sim}_seed_programmed_on_support`**, each proved from its two programmed-field axioms; **`ms3a_payload_pair_public_fields_on_support`** uses **`A_ms3a_seed_pair_public_fields_on_support`**, proved by conjoining the four **`A_ms3a_seed_pair_*_on_support`** lemmas, each proved from the matching **`A_ms3a_seed_pair_*_source_shared`** axiom and identity `from_seed`. **Proved** constructor lemmas (`ms3a_real_source_constructor_wf`, …) in `ms/source/SourceScheduleObligations.ec` consume those payload-support lemmas and **`MS_3a_bitness_layer_exact_simulation`**. Mem-pair lemmas live in `ms/source/SourceTheorem.ec`. Constructor lemmas `ms3a_pack_observable_with_digest_consistent`, `ms3a_default_transcript_digest_consistent`, and `ms3a_default_frame_consistent` keep frame wiring explicit (no anonymous admits).

`theorem/MainTheorem.ec` **`use_MS_3a`** is a **lemma** returning **`ms3a_bitness_real_sim_equiv x s`** (imports `SourceDistributions` + `SourceTheorem`).

### Remaining proof obligations (MS-3a track; axioms, not `admit`)

There is **no** `admit` left in `docs/03-formal-verification/easycrypt/*.ec`.

| Obligation | Where |
|------------|--------|
| Uniform-shift reparameterization for `duni_scalar` joint pairs | **Axiom** `duni_scalar_shift_reparam` (`ms/SchnorrBranch.ec`) |
| Seed-level bitness-layer schedule (single `dmap` per side off abstract seeds) | **Axiom** `A_ms3a_bitness_layer_seed_schedule` (`ms/source/SourceScheduleObligations.ec`) — **unconditional** equality `dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload = dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload` (core coupling target; see “Schedule axiom design” below). **Proved packaging:** `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap` (`SourceBitnessDistributions.ec`) and `L_ms3a_bitness_layer_seed_schedule_composed_form` (`SourceScheduleObligations.ec`) recover the legacy **`… \o ms3a_*_payload_from_seed`** statement |
| Payload-level `dmap` schedule (nested payload pushforwards) | **Lemma** `A_ms3a_payload_dmap_bitness_layer_schedule` (`SourceScheduleObligations.ec`) — **proved** from `A_ms3a_bitness_layer_seed_schedule` + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`ms3a_bitness_{real,sim}_source_as_seed_dmap`**. **`ms3a_payload_schedule_equivalence`** — **deprecated / compatibility wrapper** (proved; redundant `ms3a_ax_*` hypotheses unused in proof). **`ms3a_source_eq_from_bitness_layer`** — **proved** without those hypotheses |
| `ms3a_ax_real_wf`, `ms3a_ax_sim_wf`, `ms3a_ax_public_fields`, `ms3a_ax_prog_layer`, `ms3a_ax_bitness_exact` | **Proved lemmas** from payload-support lemmas + `dmap`/`supp_dmap` (`SourceScheduleObligations.ec`); **`ms3a_ax_*_from_axioms`** in `SourceTheorem.ec` |
| Seed support (programmed layer on **seed** support) | **Lemmas** `A_ms3a_real_seed_programmed_on_support`, `A_ms3a_sim_seed_programmed_on_support` from four **axioms** (`*_real_*` / `*_sim_*` bits + bitness-globals on support; `ms/source/SourceProgrammedObligations.ec`) — quantify over `d_ms3a_{real,sim}_payload_seed` only |
| Seed support (paired **public** fields on joint seed support) | **Axioms** `A_ms3a_seed_pair_stmt_source_shared`, `A_ms3a_seed_pair_res_source_shared`, `A_ms3a_seed_pair_comparison_global_source_shared`, `A_ms3a_seed_pair_bitness_globals_source_shared`; **lemmata** `A_ms3a_seed_pair_stmt_on_support`, `A_ms3a_seed_pair_res_on_support`, `A_ms3a_seed_pair_comparison_global_on_support`, `A_ms3a_seed_pair_bitness_globals_on_support` (`ms/source/SourcePublicFieldObligations.ec`); **lemma** `A_ms3a_seed_pair_public_fields_on_support` combines into `ms3a_payload_pair_public_fields_match` for `from_seed` |
| Payload support (programmed layer on payload support) | **Proved lemmas** `ms3a_payload_real_support_programmed`, `ms3a_payload_sim_support_programmed` (`ms/source/SourcePublicFieldObligations.ec`) — from real/sim programmed lemmas + defining `dmap` + `supp_dmap` |
| Payload public fields on paired payload support | **Proved lemma** `ms3a_payload_pair_public_fields_on_support` (`ms/source/SourcePublicFieldObligations.ec`); bridge **`ms3a_real_sim_public_fields_of_payload_pair`** is **proved** (`ms/source/SourceDistributionLemmas.ec`) |
| Constructor-scoped source obligations | **Proved lemmas** `ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact` (`ms/source/SourceScheduleObligations.ec`) |
| Source-constructor image predicates | `ms3a_real_source_in_constructor_image`, `ms3a_sim_source_in_constructor_image` — **definitions** (`ms/source/SourceDistributionLemmas.ec`) |
| Source distribution-in-image | `ms3a_real_source_distribution_in_image`, `ms3a_sim_source_distribution_in_image` — **proved** from `dmap` source definitions + `supp_dmap` / `distr_mem_eq` (`ms/source/SourceDistributionLemmas.ec`) |
| Source constructor image lemmas | `ms3a_real_source_constructor_image`, `ms3a_sim_source_constructor_image` — **proved** (delegate to distribution-in-image lemmas) (`ms/source/SourceDistributionLemmas.ec`) |
| Generic digest-by-construction constructor field/layout obligation | `ms3a_pack_observable_with_digest_field_correct` (`ms/SourceModel.ec`) |
| Skeleton-to-game equivalence (`ms3a_bitness_real_sim_equiv` to full game statement) | future `QssmGames` / transcript ops (explicitly out of current scope) |

### Schedule axiom design (payload coupling)

**Residual axiom (seed boundary):** **`A_ms3a_bitness_layer_seed_schedule`** states
unconditional equality of the **one-step** pushforwards
`dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload =
 dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload`.
Because **`ms3a_{real,sim}_payload_from_seed`** are **definitional identities** on the
payload-shaped seed types, the older composed form
`dmap (d_ms3a_*_payload_seed …) (ms3a_bitness_layer_source_of_* \o ms3a_*_payload_from_seed …)`
is **proved equivalent** (`eq_dmap_in`) by **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`**
(`SourceBitnessDistributions.ec`); lemma **`L_ms3a_bitness_layer_seed_schedule_composed_form`**
packages the axiom back into that legacy shape. Payload laws are **defined** as
`dmap (d_ms3a_*_payload_seed) (ms3a_*_payload_from_seed …)`, so (by **`Distr.dmap_comp`**) folded
`d_ms3a_bitness_{real,sim}_source` matches the composed seed pushforwards. Lemma
**`A_ms3a_payload_dmap_bitness_layer_schedule`** recovers the older **payload-nested** phrasing for
compatibility and for call sites that still speak in terms of `d_ms3a_*_source_payload`.

**Conceptual decomposition (for proof planning, not separate axioms):**

1. **Real payload pushforward shape** — proved: `ms3a_bitness_real_source_as_seed_dmap`.
2. **Sim payload pushforward shape** — proved: `ms3a_bitness_sim_source_as_seed_dmap`.
3. **Identity collapse on seeds** — proved: `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`.
4. **Common bitness-layer image** — the **equality** of the two seed pushforwards (layer maps off abstract seeds) is exactly **`A_ms3a_bitness_layer_seed_schedule`** (still one coupling obligation).
5. **Public-field alignment** — separate **seed** axioms `A_ms3a_seed_pair_*_source_shared` (they do **not** imply the schedule: they omit **`ms3rp_transcript_digest` / `ms3sp_transcript_digest`**, so transcript-digest coupling is **not** captured by the four paired-public axioms alone).

**Tradeoff:** the schedule axiom remains **unconditional** (stronger than a premise-driven implication on `ms3a_ax_*` alone). The five `ms3a_ax_*` predicates stay **proved lemmas**
from payload-support lemmas (from seed axioms), not schedule side-conditions.

**`ms3a_payload_schedule_equivalence`:** treat as **legacy / wrapper** packaging
only. New proofs should cite **`A_ms3a_bitness_layer_seed_schedule`**, lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`**, or **`ms3a_source_eq_from_bitness_layer`**; do not read the five `ms3a_payload_schedule_equivalence` hypotheses as part of the schedule proof obligation.

## Seed distribution concretization (design audit)

This section records **what must become concrete** so abstract
`d_ms3a_{real,sim}_payload_seed` can eventually discharge the MS-3a seed axioms and
**`A_ms3a_bitness_layer_seed_schedule`**, without editing `.ec` proofs here.

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
coupling is **orthogonal** to the four `A_ms3a_seed_pair_*_source_shared` axioms and is
exactly why **`A_ms3a_bitness_layer_seed_schedule`** cannot be derived from those four
axioms alone.

### Proposed concrete seed architecture (high level)

**Option A — Joint / coupling seed (recommended pattern; mirrors MS-3c comparison lane).**

- Introduce a **joint** distribution `d_ms3a_payload_seed_coupling x s` over pairs
  `(sr, ss)` (or over a shared “spine” record plus sim-only residual) such that on support,
  the four public fields of `sr` and `ss` agree and programmed-vector hypotheses hold.
- Define **`d_ms3a_real_payload_seed x`** as **`dmap` of the joint** (first projection +
  reshaping) and **`d_ms3a_sim_payload_seed x s`** as **`dmap` of the joint** (second
  projection), possibly with an extra `dmap` for sim-only randomness keyed by `s`.
- Then **`A_ms3a_seed_pair_*_source_shared`** become **proved** from **`supp_dmap`** on
  the joint (same as `L_ms3c_*` marginal/support style lemmas in the comparison
  coupling chain).
- **`A_ms3a_bitness_layer_seed_schedule`** reduces to proving that the **two** `dmap`
  pushforwards of the **same** joint through the two typed layer maps coincide — typically
  via a **single** `dmap` off the joint through a map that ignores the sim/real tag, or
  via **`eq_dmap_in`** after showing pointwise agreement on support.

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

**Shared public fields (design intent).** The four `source_shared` axioms are the
**minimal** joint constraints needed for constructor lemmas that ignore transcript
digest. **Bitness globals** enter through **`ms_ordered_challenge_vector_matches`** on
seed support (programmed axioms) and through pairing.

**Transcript digest.** Must be tied to **`ms_transcript_digest_public_fields`** /
**`ms_transcript_digest_of_observable`** (`TranscriptObservable.ec`) and the abstract
frame (`SourceModel.ec`) when moving from source to **`d_ms3a_bitness_*_observable_v2`**.
Expect **game-level** or **linking** axioms unless digest is defined as a pure function of
the already-committed public fields on support.

**How both push to the “same” bitness-layer source.** For **values** on joint support,
`ms3a_bitness_layer_source_of_real_payload sr` and `ms3a_bitness_layer_source_of_sim_payload
ss` are **equal** when all six fields agree; the schedule axiom is the **distributional**
version of that fact.

### Axiom → intended discharge (definitions / lemmas)

| Obligation | Discharge strategy (when seeds are concretized) |
|------------|--------------------------------------------------|
| **`A_ms3a_bitness_layer_seed_schedule`** | Joint law + `eq_dmap` / `eq_dmap_in` / marginalization; or one explicit game invariant proving equality of pushforwards. |
| **`A_ms3a_real_seed_bits_programmed_on_support`** | From construction of `bits` from programmed transcript / ROM (`ms_per_bit_programmed`); may remain **lemma from game** until transcript ops are concrete. |
| **`A_ms3a_real_seed_bitness_globals_programmed_on_support`** | Same, plus list alignment for **`ms_ordered_challenge_vector_matches`**. |
| **`A_ms3a_sim_seed_bits_programmed_on_support`** | Same as real, keyed by `s` if sim uses explicit simulator randomness. |
| **`A_ms3a_sim_seed_bitness_globals_programmed_on_support`** | Same as real on sim side. |
| **`A_ms3a_seed_pair_stmt_source_shared`** | Joint coupling / identical spine sampling / `supp_dprod`-style proof. |
| **`A_ms3a_seed_pair_res_source_shared`** | Same. |
| **`A_ms3a_seed_pair_comparison_global_source_shared`** | Same. |
| **`A_ms3a_seed_pair_bitness_globals_source_shared`** | Same. |

**Already packaged (no seed concretization needed for proof shape).**
`A_ms3a_{real,sim}_seed_programmed_on_support`, `A_ms3a_seed_pair_*_on_support`,
`A_ms3a_seed_pair_public_fields_on_support`, payload support lemmas — these **rewrite**
to seed statements and are done once the four field axioms hold.

### Blockers (read-only audit)

| Blocker | Why it matters |
|---------|----------------|
| **`ms_public_input`** is an abstract type (`QssmTypes.ec`) | **Mitigation (surface only):** six uninterpreted projections **`ms3a_public_*`** + shape preds **`ms3a_public_{bitness,transcript}_shape_ok`** in **`ms/SourceModel.ec`** mirror the MS-3a seed / v2 field order; **linking** those ops to sampled seeds / games still requires future axioms or definitions (no semantics added yet). |
| **`ms_transcript_observable`** + **`ms3a_observable_of_v2`** abstract | Observable pushforwards (`SourceObservableDistributions.ec`) stay abstract until the v2 ↔ abstract link is constructive beyond **`A_ms3a_observable_of_v2_aligns`**. |
| **`ms_transcript_digest_public_fields`** abstract | Digest cell consistency (`ms_transcript_digest_of_observable`) cannot be proved from source fields alone until digest is a **function** of committed public fields or a game supplies equality. |
| **ROM / FS / `duni_scalar` wiring** | Programmed-bit axioms talk about **`ms_per_bit_programmed`** and challenge splits; concrete seeds must **factor** the same ROM hypotheses used in `BitnessOne` / `FS.ec`. |
| **Game views / witnesses** | Until `G_MS_*` views expose the actual samplers for bitness-after-*, schedule and seed axioms are **orphans** relative to `game_pr`. |
| **Typed real vs sim payloads** | Schedule needs a **semantic** coupling argument, not just record equality, because EasyCrypt keeps `ms3a_bitness_layer_source_of_*` as two operators. |

### Public spine projections (`ms/SourceModel.ec`)

| `op` / `pred` | Role |
|----------------|------|
| **`ms3a_public_stmt_digest`**, **`ms3a_public_result_bit`**, **`ms3a_public_bits`**, **`ms3a_public_bitness_globals`**, **`ms3a_public_comparison_global`**, **`ms3a_public_transcript_digest`** | Uninterpreted projections from **`ms_public_input`**, aligned to the six MS-3a seed / v2 fields. |
| **`ms3a_public_bitness_shape_ok`** | `V2_BIT_COUNT` list lengths for bits + bitness globals (`BitnessVector`). |
| **`ms3a_public_transcript_shape_ok`** | **`ms_transcript_digest_of_observable`** on the v2 record built via **`ms3a_pack_observable`** from the six projections (digest cell vs public-field digest). |

No new axioms; seed laws and schedule axioms unchanged.

### Smallest **safe** implementation patch (recommended order)

1. **Projection / query ops** — **partially done:** abstract **`ms3a_public_*`** spine + narrow shape preds in **`SourceModel.ec`**. Next: link them to games/spec (and, if needed, add view-record projections) **without** guessed sampling. This unlocks Phase-1-style **length and index** reasoning (as in MS-3c) once equalities are assumed or proved.
2. **Introduce a joint seed coupling** theory fragment (parallel to
   **`ComparisonCoupling*`**): one `distr` for pairs + marginal lemmas. Instantiate
   **`d_ms3a_real_payload_seed`** / **`d_ms3a_sim_payload_seed`** as marginals. This is
   the **lowest-risk** path to eliminate **`A_ms3a_bitness_layer_seed_schedule`** and the
   four **`source_shared`** axioms in one architectural move.
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
- Split the old “one-shot” source equality story: the **schedule** residual is axiom **`A_ms3a_bitness_layer_seed_schedule`** (single `dmap` per side at the abstract seed through the layer maps; legacy **`from_seed`** composition is **proved** redundant via **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`**). Lemma **`A_ms3a_payload_dmap_bitness_layer_schedule`** is the former payload-level statement, now **proved** from that axiom + **`L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap`** + **`dmap_comp`** (`ms3a_bitness_*_source_as_seed_dmap`). The former `ms3a_ax_*` premises are **proved lemmas** unpacking support from the three **payload-support lemmas**, which in turn follow from **seed-support** (real/sim programmed lemmas each from two field axioms + four paired-public **source_shared** axioms + lemmata `A_ms3a_seed_pair_stmt_on_support`, `A_ms3a_seed_pair_res_on_support`, `A_ms3a_seed_pair_comparison_global_on_support`, `A_ms3a_seed_pair_bitness_globals_on_support`, `A_ms3a_seed_pair_public_fields_on_support`) and the defining payload `dmap`s; **`ms3a_payload_schedule_equivalence`** is **deprecated / compatibility** packaging (ignores those hypotheses). **`ms3a_source_eq_from_bitness_layer`** unfolds folded `d_ms3a_bitness_*_source` and applies **`A_ms3a_payload_dmap_bitness_layer_schedule`**.
- **Constructor obligations** formerly axiomatized at the folded-source layer are now **proved lemmas**: WF and programmed-bitness use payload support lemmas; public-field agreement uses `ms3a_payload_pair_public_fields_on_support` and **`ms3a_real_sim_public_fields_of_payload_pair`**; per-index exact simulation rewrites the programmed-vector hypothesis with the `dmap` preimage equality (`-Heqr`) and calls **`MS_3a_bitness_layer_exact_simulation`**. **forall** intros on paired real/sim binders use the quantifier order `(stmt_r stmt_s …)` (not “all real then all sim”) so constructor arguments type-check.

## Next target

**MS-3a residual:** discharge axiom **`A_ms3a_bitness_layer_seed_schedule`** (payload schedule **`A_ms3a_payload_dmap_bitness_layer_schedule`** is then a **proved** corollary) and the remaining **seed obligations**: four programmed-on-support **axioms** (**`A_ms3a_real_seed_bits_programmed_on_support`**, **`A_ms3a_real_seed_bitness_globals_programmed_on_support`**, **`A_ms3a_sim_seed_bits_programmed_on_support`**, **`A_ms3a_sim_seed_bitness_globals_programmed_on_support`**, each packaged by proved lemmas **`A_ms3a_{real,sim}_seed_programmed_on_support`**); four paired-public **source_shared** **axioms** (**`A_ms3a_seed_pair_stmt_source_shared`**, **`A_ms3a_seed_pair_res_source_shared`**, **`A_ms3a_seed_pair_comparison_global_source_shared`**, **`A_ms3a_seed_pair_bitness_globals_source_shared`**, with proved **`A_ms3a_seed_pair_*_on_support`** lemmata for `from_seed` payloads); instantiate abstract **`d_ms3a_{real,sim}_payload_seed`** from the execution spec / games (`ms3a_*_payload_from_seed` is definitional identity on payload-shaped seeds; **`A_ms3a_seed_pair_public_fields_on_support`** is already a **proved lemma**). Optionally **`ms3a_pack_observable_with_digest_field_correct`** and **`duni_scalar_shift_reparam`**.

**MS-3b** (`MS_3b_true_clause_characterization`) is the **recommended next milestone** once the remaining MS-3a axiom surface above is acceptable: folded-source constructor lemmas are no longer axioms, and folded real/sim source equality is proved via **`A_ms3a_payload_dmap_bitness_layer_schedule`** (from the seed schedule axiom + `dmap_comp`; the five `ms3a_ax_*` predicates are separate proved lemmas, not schedule premises).
