# MS-3a Proof Plan (EasyCrypt)

This note is **design + formal target tracking** for MS-3a. **`MS_3a_exact_bitness_simulation` is not vacuous**: it proves the predicate **`ms3a_bitness_real_sim_equiv`** (equality of abstract `ms_transcript_observable` distributions) via the layered lemma **`MS_3a_exact_bitness_simulation_from_layers`**. The skeleton admit is now discharged via a named packaging bridge lemma; remaining open obligations are listed in the checklist.

## Exact statement (theorem layer)

From `docs/02-protocol-specs/qssm-zk-theorem-spec.md`:

- **MS-3a**: exact bitness transcript simulation under programmed challenges.

Intended meaning (informal): once the bitness Fiat–Shamir query is programmed, every witness-using bitness branch is **distribution-identical** to a simulated Schnorr branch on the frozen observable boundary (zero residual advantage term).

## What is now formalized (single-branch core)

File: **`QssmSchnorrSingleBit.ec`** (after `QssmTypes.ec`; see `check_easycrypt.sh`).

### Observable distributions (equality target)

Both are values of type `schnorr_single_bit_obsv distr` (i.e. distributions over `sch_point * scalar`):

- **Real** `d_ms3a_schnorr_real w c`: draw `alpha <- duni_scalar`, output `(alpha * H, alpha + c * w)`.
- **Sim** `d_ms3a_schnorr_sim w c`: draw `z <- duni_scalar`, output `(z * H - c * (w * H), z)` with `w * H` written as `sch_pubkey w`.

**Lemma** `MS_3a_single_branch_schnorr_reparam`: `forall w c, d_ms3a_schnorr_real w c = d_ms3a_schnorr_sim w c` — **proved** from:
- `duni_scalar_shift_reparam` (uniform-shift/bijection reparameterization axiom), and
- point algebra (`sch_sim_announcement_reparam`).
This moves the open obligation from a proof-body admit to one explicit, non-cryptographic uniformity axiom.

### Proved algebraic lemmas (no longer axioms)

- `sch_neutralR`, `sch_add_pt_oppR`, `sch_pt_add_cancel`, `sch_smul_sub_gen`, `sch_sim_announcement_reparam` — see `QssmSchnorrSingleBit.ec`.

## Axiom inventory in `QssmSchnorrSingleBit.ec` (classification)

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

## Fiat–Shamir / programmed challenge surface (`QssmFS.ec`)

Execution-spec anchor: **`qssm-zk-concrete-execution-spec.md` section F** (Engine B v2 query/challenge path). Label strings live in `QssmDomains.ec` (`LABEL_MS_V2_BITNESS_QUERY`, `LABEL_MS_V2_QUERY_SCALAR`); no new labels in EC.

| Name | Role |
|------|------|
| `ms_bitness_query_digest` | Abstract `hash_domain(DOMAIN_MS, [label, statement_digest, bit_index, announce_zero, announce_one])` at digest level. |
| `ms_query_to_scalar` | Abstract `hash_to_scalar(LABEL_MS_V2_QUERY_SCALAR, [query_digest])`. |
| `ms_bitness_fs_scalar stmt i d0 d1` | Composite `ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1)` — global FS scalar for one bitness query. |
| `ms_bitness_fs_programmed stmt i d0 d1 cglob` | Predicate `cglob = ms_bitness_fs_scalar stmt i d0 d1` (cglob **not** free once this holds). |
| `A2_bitness_programmed_challenge` | **Proved lemma**, exact instance of **`A2_programmable_oracle_exists`** at digest `ms_bitness_query_digest stmt i d0 d1` — **not** a new cryptographic axiom. |

## One-bit OR bitness model (`QssmMSBitnessSingle.ec`)

**Location:** after `QssmFS.ec`, before `QssmMS.ec`. **Imports:** `QssmSchnorrSingleBit`, **`QssmFS`**.

### Transcript shape

Record **`ms_single_bit_or_transcript`**: statement digest `msbt_stmt`, public points `msbt_pub0` / `msbt_pub1`, branch observables `msbt_branch0` / `msbt_branch1`, challenges `msbt_challenge_zero` / `msbt_challenge_one`, global `msbt_global_challenge`.

**Split:** `ms_challenges_split c0 c1 cglob` ↔ `sch_s_add c0 c1 = cglob`.

**Programmed one-bit relation** `ms_single_bit_programmed_bitness_transcript stmt i P0 P1 o0 o1 c0 c1 cglob`: announcements match observables (`o0.`1, `o1.`1), split holds, and `ms_bitness_fs_programmed` on digests `ms_single_bit_branch_digest P0` / `P1` (abstract lane material for section F preimages).

### Joint distributions on `(branch0, branch1)`

- **`d_ms_bit_or_real_bitfalse` / `d_ms_bit_or_real_bittrue` / `d_ms_bit_or_sim_both`** — unchanged.
- **`d_ms_bit_or_pack`** — unchanged.

### OR-split lemmas (proved modulo `MS_3a_single_branch_schnorr_reparam`)

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

**Rust/spec anchors:** `internals.rs`, execution spec F.

**Refined vs earlier plan:** `cglob` can be tied to `ms_bitness_fs_scalar` via `ms_bitness_fs_programmed`; digest wiring for announcements is still abstract (`ms_single_bit_branch_digest`).

## Assumptions needed (system level)

- **`A2_programmable_oracle_exists`** (`QssmFS.ec`) — ROM / programming surface.
- No leakage beyond observable boundary.
- Model linking `duni_scalar` to `hash_to_scalar` / ROM.

## Checklist

| Item | Status |
|------|--------|
| `MS_3a_single_branch_schnorr_reparam` | **Proved** (`QssmSchnorrSingleBit.ec`) from `duni_scalar_shift_reparam` + `sch_sim_announcement_reparam` |
| OR-split lemmas | **Proved** |
| `ms_bitness_fs_scalar` / `ms_bitness_fs_programmed` | **Definitions** (`QssmFS.ec`) |
| `A2_bitness_programmed_challenge` | **Proved** (from `A2_programmable_oracle_exists`) |
| `MS_3a_single_bit_bitness_fs_consistent`, `MS_3a_single_bit_programmed_or_split_exact_simulation` | **Proved** |
| `MS_3a_ordered_challenge_vector_consistency`, `MS_3a_all_bits_from_single_bit` | **Proved** (`QssmMSBitnessVector.ec`) |
| `MS_3a_bitness_layer_exact_simulation` | **Proved** — for each valid index, unpack `ms_per_bit_programmed` at `ms_nth_single_bit_or bits i`, extract FS+split, and instantiate `MS_3a_single_bit_programmed_or_split_exact_simulation` |
| `MS_3a_observable_bitness_challenges_consistent`, `MS_3a_observable_transcript_digest_consistent` | **Proved** (`QssmMSTranscriptObservable.ec`) |
| `MS_3a_bitness_layer_to_observable_exact_simulation` | **Proved** — delegates per-index OR packaging through `MS_3a_bitness_layer_exact_simulation`; observable/digest hypotheses reserved for game marginal |
| `d_ms3a_bitness_real_source`, `d_ms3a_bitness_sim_source` | **Structured source distrs** (`QssmMS.ec`) over `{stmt, result, bits, bitness_glob, comparison_glob, transcript_digest}` |
| `ms3a_pack_observable`, `d_ms3a_bitness_*_observable_v2` | **Defined** (`QssmMS.ec`) via `dmap` from structured source into canonical `ms_v2_transcript_observable` |
| `d_ms3a_bitness_real_observable`, `d_ms3a_bitness_sim_observable` | **Defined** (`QssmMS.ec`) via `dlet` pushforward from v2 observable through `ms3a_observable_of_v2` |
| `ms3a_bitness_real_sim_equiv` | **Predicate** — `d_ms3a_bitness_real_observable x = d_ms3a_bitness_sim_observable x s` |
| `ms3a_frame_consistent`, `ms3a_packed_frame` | **Predicates** — reusable frame consistency + packed-field constructor relation |
| `MS_3a_frame_consistent_of_v2` | **Proved** (`QssmMS.ec`) — derives alignment+digest frame from `ms_transcript_digest_of_observable` using `A_ms3a_observable_of_v2_aligns` |
| `ms3a_source_observable_equiv_from_layer` | **Proved bridge lemma** (`QssmMS.ec`) — source distribution equality implies packed/pushforward observable equality (`ms3a_bitness_real_sim_equiv`) |
| `MS_3a_exact_bitness_simulation_from_layers` | **Proved** (`QssmMS.ec`) — reduced to `ms3a_source_observable_equiv_from_layer` using named source-equality premise |
| `MS_3a_exact_bitness_simulation` | **Lemma** (`QssmMS.ec`) — wrapper now uses named obligations `ms3a_default_source_eq` and `ms3a_default_frame_consistent` (no anonymous admit) |

## All-bit bitness lift (`QssmMSBitnessVector.ec`)

**Status (MS-3a vector layer):** **wired** — definitions and composition predicates in place (`V2_BIT_COUNT = 64`, per-bit programmed transcript, ordered global challenge digest vector, `ms_transcript_bitness_digests_match_vector`). List order models ordered `ms_bitness_global_challenges` / execution-spec bitness challenge vector.

**Single-bit FS + OR layer:** **complete** (`QssmMSBitnessSingle.ec` + `QssmFS.ec` hooks).

## Transcript observable layer (`QssmMSTranscriptObservable.ec` + `QssmMS.ec`)

**Canonical record** `ms_v2_transcript_observable` (statement digest, result bit, `msv2_bitness_global_challenges`, comparison digest, transcript digest).

**Relations:** `ms_bitness_vector_matches_observable` (bitness list + stmt + result), `ms_transcript_digest_of_observable` (digest cell vs abstract `ms_transcript_digest_public_fields`).

**Abstract link + packaging:** `ms_abstract_observable_aligns_v2`, `ms3a_observable_of_v2`, `ms3a_pack_observable`, and `ms3a_packed_frame` in `QssmMS.ec` tie canonical v2 observables to the abstract transcript surface.

## MS-3a global statement (layered)

- **`MS_3a_exact_bitness_simulation_from_layers`** — hypotheses track single-branch reparam, OR-split, A2 bitness ROM corollary, vector bitness layer, observable bridge, and **`ms3a_frame_consistent obs o`**; proof closes via **`ms3a_source_observable_equiv_from_layer`** plus a named source-equality premise.
- **`MS_3a_exact_bitness_simulation`** — applies the skeleton with concrete lemma proof terms; `ms3a_default_source_eq` is now **proved** by reducing arbitrary sampled sources to explicit constructors (`ms3a_make_real_source`, `ms3a_make_sim_source`) via image lemmas, then applying the premise-driven source-packaging axiom `ms3a_source_eq_from_bitness_layer` with constructor-scoped obligations (`ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact`). Constructor lemmas `ms3a_pack_observable_with_digest_consistent`, `ms3a_default_transcript_digest_consistent`, and `ms3a_default_frame_consistent` keep frame wiring explicit (no anonymous admits).

`QssmTheorem.ec` **`use_MS_3a`** is a **lemma** returning **`ms3a_bitness_real_sim_equiv x s`**.

### Remaining admits (MS-3a track)

| Obligation | Where |
|------------|--------|
| Uniform-shift reparameterization for `duni_scalar` pairs | `duni_scalar_shift_reparam` (`QssmSchnorrSingleBit.ec`) |
| Generic source-packaging equality obligation (premise-driven) | `ms3a_source_eq_from_bitness_layer` (`QssmMS.ec`) |
| Constructor-scoped source obligations | `ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact` (`QssmMS.ec`) |
| Source-constructor image predicates | `ms3a_real_source_in_constructor_image`, `ms3a_sim_source_in_constructor_image` (`QssmMS.ec`) |
| Source distribution-in-image obligations | `ms3a_real_source_distribution_in_image`, `ms3a_sim_source_distribution_in_image` (`QssmMS.ec`) |
| Source constructor image lemmas | `ms3a_real_source_constructor_image`, `ms3a_sim_source_constructor_image` (**proved wrappers** in `QssmMS.ec`) |
| Generic digest-by-construction constructor field/layout obligation | `ms3a_pack_observable_with_digest_field_correct` (`QssmMS.ec`) |
| Skeleton-to-game equivalence (`ms3a_bitness_real_sim_equiv` to full game statement) | future `QssmGames` / transcript ops (explicitly out of current scope) |

## Next target

**Close one major lower obligation next:** derive/remove `ms3a_source_eq_from_bitness_layer` itself from explicit constructor-level source semantics and bitness-layer/packing lemmas, then replace distribution-in-image obligations (`ms3a_real_source_distribution_in_image`, `ms3a_sim_source_distribution_in_image`) with definitional proofs from concrete source constructors. Optionally derive/remove `ms3a_pack_observable_with_digest_field_correct` and `duni_scalar_shift_reparam` from stronger library-level finite-field/hash-layout facts if available in your chosen EasyCrypt model.
