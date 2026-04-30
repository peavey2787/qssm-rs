# MS-3a Proof Plan (EasyCrypt)

This note is **design + formal target tracking** for MS-3a. **`MS_3a_exact_bitness_simulation` is not vacuous**: it proves the predicate **`ms3a_bitness_real_sim_equiv`** (equality of abstract `ms_transcript_observable` distributions) via the layered lemma **`MS_3a_exact_bitness_simulation_from_layers`**. The skeleton admit is now discharged via a named packaging bridge lemma; remaining open obligations are listed in the checklist.

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

**Source packaging (`ms/source/SourceTypes.ec`, `SourceConstructors.ec`, `SourceDistributions.ec`):** `ms3a_real_source_payload` / `ms3a_sim_source_payload` are record types whose fields match the arguments to `ms3a_make_real_source` / `ms3a_make_sim_source`. Laws `d_ms3a_bitness_real_source` / `d_ms3a_bitness_sim_source` are **by definition** `dmap` of abstract payload distributions through those constructors (via `ms3a_bitness_layer_source_of_{real,sim}_payload`).

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
| `d_ms3a_real_source_payload`, `d_ms3a_sim_source_payload` | **Abstract payload distrs** (`ms/source/SourceDistributions.ec`) — scheduling from `ms_public_input` / `seed` |
| `d_ms3a_bitness_real_source`, `d_ms3a_bitness_sim_source` | **Defined** (`ms/source/SourceDistributions.ec`) as `dmap` pushforwards of payload laws through `ms3a_bitness_layer_source_of_{real,sim}_payload` (wrappers over `ms3a_make_*_source`) |
| `dmap` preimage / membership for `d_ms3a_bitness_*_source` | **Proved** — `case/supp_dmap` on `Distr.supp_dmap` plus local `distr_mem_eq` (`ms/source/SourceDistributions.ec`; **MS-3a hardening**, not MS-3b) |
| `ms3a_pack_observable` | **Defined** (`ms/SourceModel.ec`) — canonical v2 packer |
| `d_ms3a_bitness_*_observable_v2`, `d_ms3a_bitness_*_observable`, `ms3a_bitness_real_sim_equiv` (pred), `ms3a_source_observable_equiv_from_layer` | **Defined / proved** (`ms/source/SourceDistributions.ec`) — `dmap` / `dlet` from structured source and abstract pushforward |
| `ms3a_frame_consistent`, `ms3a_packed_frame` | **Predicates** (`ms/SourceModel.ec`) — reusable frame consistency + packed-field constructor relation |
| `MS_3a_frame_consistent_of_v2` | **Proved** (`ms/SourceModel.ec`) — derives alignment+digest frame from `ms_transcript_digest_of_observable` using `A_ms3a_observable_of_v2_aligns` |
| `MS_3a_exact_bitness_simulation_from_layers` | **Proved** (`ms/source/SourceTheorem.ec`) — reduced to `ms3a_source_observable_equiv_from_layer` using named source-equality premise |
| `MS_3a_exact_bitness_simulation` | **Lemma** (`ms/source/SourceTheorem.ec`) — wrapper now uses named obligations `ms3a_default_source_eq` and `ms3a_default_frame_consistent` (no anonymous admit) |

## All-bit bitness lift (`ms/BitnessVector.ec`)

**Status (MS-3a vector layer):** **wired** — definitions and composition predicates in place (`V2_BIT_COUNT = 64`, per-bit programmed transcript, ordered global challenge digest vector, `ms_transcript_bitness_digests_match_vector`). List order models ordered `ms_bitness_global_challenges` / execution-spec bitness challenge vector.

**Single-bit FS + OR layer:** **complete** (`ms/BitnessOne.ec` + `primitives/FS.ec` hooks).

## Transcript observable layer (`ms/TranscriptObservable.ec` + `ms/SourceModel.ec`)

**Canonical record** `ms_v2_transcript_observable` (statement digest, result bit, `msv2_bitness_global_challenges`, comparison digest, transcript digest).

**Relations:** `ms_bitness_vector_matches_observable` (bitness list + stmt + result), `ms_transcript_digest_of_observable` (digest cell vs abstract `ms_transcript_digest_public_fields`).

**Abstract link + packaging:** `ms_abstract_observable_aligns_v2`, `ms3a_observable_of_v2`, `ms3a_pack_observable`, and `ms3a_packed_frame` in `ms/SourceModel.ec` tie canonical v2 observables to the abstract transcript surface.

## MS-3a global statement (layered)

- **`MS_3a_exact_bitness_simulation_from_layers`** — hypotheses track single-branch reparam, OR-split, A2 bitness ROM corollary, vector bitness layer, observable bridge, and **`ms3a_frame_consistent obs o`**; proof closes via **`ms3a_source_observable_equiv_from_layer`** plus a named source-equality premise.
- **`MS_3a_exact_bitness_simulation`** — applies the skeleton with concrete lemma proof terms; `ms3a_default_source_eq` is now **proved** by reducing arbitrary sampled sources to explicit constructors (`ms3a_make_real_source`, `ms3a_make_sim_source`) via image lemmas, then applying the **proved** lemma `ms3a_source_eq_from_bitness_layer` (unfolds folded `d_ms3a_bitness_*_source` to payload `dmap`s and invokes **`ms3a_payload_schedule_equivalence`**) together with **proved** constructor lemmas (`ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact`) in `ms/source/SourceObligations.ec` derived from payload support axioms and **`MS_3a_bitness_layer_exact_simulation`**. Mem-pair / default-source lemmas live in `ms/source/SourceTheorem.ec`. Constructor lemmas `ms3a_pack_observable_with_digest_consistent`, `ms3a_default_transcript_digest_consistent`, and `ms3a_default_frame_consistent` keep frame wiring explicit (no anonymous admits).

`theorem/MainTheorem.ec` **`use_MS_3a`** is a **lemma** returning **`ms3a_bitness_real_sim_equiv x s`** (imports `SourceDistributions` + `SourceTheorem`).

### Remaining proof obligations (MS-3a track; axioms, not `admit`)

There is **no** `admit` left in `docs/03-formal-verification/easycrypt/*.ec`.

| Obligation | Where |
|------------|--------|
| Uniform-shift reparameterization for `duni_scalar` joint pairs | **Axiom** `duni_scalar_shift_reparam` (`ms/SchnorrBranch.ec`) |
| Payload-level scheduling (`dmap` equality under `ms3a_ax_*`) | **Axiom** `ms3a_payload_schedule_equivalence` (`ms/source/SourceObligations.ec`); folded source equality **`ms3a_source_eq_from_bitness_layer`** is a **proved lemma** from it |
| Payload support (programmed layer on support) | **Axioms** `ms3a_payload_real_support_programmed`, `ms3a_payload_sim_support_programmed` (`ms/source/SourceObligations.ec`) |
| Payload public fields on support | **Axiom** `ms3a_payload_pair_public_fields_on_support` (`ms/source/SourceObligations.ec`); bridge **`ms3a_real_sim_public_fields_of_payload_pair`** is **proved** (`ms/source/SourceDistributions.ec`) |
| Constructor-scoped source obligations | **Proved lemmas** `ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact` (`ms/source/SourceObligations.ec`) |
| Source-constructor image predicates | `ms3a_real_source_in_constructor_image`, `ms3a_sim_source_in_constructor_image` — **definitions** (`ms/source/SourceDistributions.ec`) |
| Source distribution-in-image | `ms3a_real_source_distribution_in_image`, `ms3a_sim_source_distribution_in_image` — **proved** from `dmap` source definitions + `supp_dmap` / `distr_mem_eq` (`ms/source/SourceDistributions.ec`) |
| Source constructor image lemmas | `ms3a_real_source_constructor_image`, `ms3a_sim_source_constructor_image` — **proved** (delegate to distribution-in-image lemmas) (`ms/source/SourceDistributions.ec`) |
| Generic digest-by-construction constructor field/layout obligation | `ms3a_pack_observable_with_digest_field_correct` (`ms/SourceModel.ec`) |
| Skeleton-to-game equivalence (`ms3a_bitness_real_sim_equiv` to full game statement) | future `QssmGames` / transcript ops (explicitly out of current scope) |

## MS-3a hardening (completed in this phase; not MS-3b)

- Replaced the polymorphic **`dmap_source_constructor_in_image`** axiom with **`supp_dmap`** (`Distr`) and a small proved **`distr_mem_eq`** helper; mem-pair / WF lemmas use `case/supp_dmap` and preserved membership hypotheses where proof terms require terms, not bare formulas.
- Split the old “one-shot” source equality axiom: **`ms3a_payload_schedule_equivalence`** (formerly named `ms3a_bitness_payload_pushforward_schedule`) states explicit **payload `dmap` equality** under the same `ms3a_ax_*` premises; **`ms3a_source_eq_from_bitness_layer`** is proved by unfolding the folded `d_ms3a_bitness_*_source` definitions.
- **Constructor obligations** formerly axiomatized at the folded-source layer are now **proved lemmas**: WF and programmed-bitness use payload support axioms; public-field agreement uses `ms3a_payload_pair_public_fields_on_support` and **`ms3a_real_sim_public_fields_of_payload_pair`**; per-index exact simulation rewrites the programmed-vector hypothesis with the `dmap` preimage equality (`-Heqr`) and calls **`MS_3a_bitness_layer_exact_simulation`**. **forall** intros on paired real/sim binders use the quantifier order `(stmt_r stmt_s …)` (not “all real then all sim”) so constructor arguments type-check.

## Next target

**MS-3a residual:** derive or replace the four payload axioms (`ms3a_payload_real_support_programmed`, `ms3a_payload_sim_support_programmed`, `ms3a_payload_pair_public_fields_on_support`, `ms3a_payload_schedule_equivalence`) from execution-spec / payload definitions, and optionally **`ms3a_pack_observable_with_digest_field_correct`** and **`duni_scalar_shift_reparam`**.

**MS-3b** (`MS_3b_true_clause_characterization`) is the **recommended next milestone** once the remaining MS-3a axiom surface above is acceptable: folded-source constructor lemmas are no longer axioms, and no axiom states folded real/sim source equality without explicit `ms3a_ax_*` / payload premises.
