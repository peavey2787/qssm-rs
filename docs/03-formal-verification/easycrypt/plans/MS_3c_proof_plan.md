# MS-3c Proof Plan (EasyCrypt)

This note tracks **exact comparison-clause simulation** under programmed Fiat–Shamir. Definitions and the main skeleton lemma live in the split MS-3c modules under **`ms/comparison/*.ec`** (re-exported by **`ms/Comparison.ec`**). **Payloads** split across **`ComparisonPayloadTypes.ec`**, **`ComparisonPayloadSeeds.ec`**, **`ComparisonPayloadSupport.ec`**, **`ComparisonPayloadFalseClause.ec`**, with **`ComparisonPayload.ec`** as a thin **`require export`** facade (imports still use theory **`ComparisonPayload`**). **Coupling** splits across **`ComparisonCouplingTypes.ec`**, **`ComparisonCouplingAxioms.ec`**, **`ComparisonCouplingMarginals.ec`**, **`ComparisonCouplingSchedule.ec`**, with **`ComparisonCouplingTheorem.ec`** and **`ComparisonCoupling.ec`** as facades. **`ms/MS.ec`** exports the wrapper lemma **`MS_3c_exact_comparison_simulation`** (same proof as `MS_3c_exact_comparison_simulation_from_clauses` in `ms/comparison/ComparisonTheorem.ec`).

## Goal (informal)

The comparison lane should be **distributionally identical** real vs sim on `ms_comparison_clause_surface`: false branches simulator-shaped, true branch consistent with **MS-3b** blinder points and Schnorr reparameterization, FS query digest from **announcement-only** material, ROM programmability (**A2**), and challenge-share / global-challenge packaging.

## Surface and payloads (`ms/comparison/*.ec`)

- Record **`ms_comparison_clause_surface`** (indices, announcements, shares, global / query / programmed digests).
- Canonical payload **`ms3c_comparison_clause_payload`** with `mscp_*` fields (same shape as the surface record); named aliases **`ms3c_real_comparison_payload`** and **`ms3c_sim_comparison_payload`** (currently identical to the canonical payload type).
- Constructors **`ms3c_make_real_clause_surface`**, **`ms3c_make_sim_clause_surface`** (both delegate to **`ms3c_make_clause_surface`**) fold payloads into **`ms_comparison_clause_surface`**.
- **Announcement digest list (concrete list shape):** **`ms3c_digest_true_announcement`**, **`ms3c_digest_false_announcements`**, **`ms3c_clause_ann_digests_from_surface`**, and **`ms3c_clause_ann_digests c`** (= **`ms3c_clause_ann_digests_from_surface c`**) build the ordered list **`[digest(true)] ++ map digest(false_i)]`**, reusing **`ms_single_bit_branch_digest`** from **`ms/BitnessOne.ec`** for each Schnorr announcement point. Arity **`ms3c_ann_digest_list_shape`** is a **proved** consequence (**`L_ms3c_ann_digest_list_shape`**) for every surface.
- Abstract payload laws **`d_ms3c_real_comparison_payload`**, **`d_ms3c_sim_comparison_payload`** (scheduling from `ms_public_input` / `seed`).
- **Schedules** are **`dmap`** pushforwards:
  - `d_ms3c_real_comparison_schedule x = dmap (d_ms3c_real_comparison_payload x) ms3c_make_real_clause_surface`
  - `d_ms3c_sim_comparison_schedule x s = dmap (d_ms3c_sim_comparison_payload x s) ms3c_make_sim_clause_surface`
- **Surface** **`d_ms3c_comparison_{real,sim}_clause`** remain definitionally equal to those schedules.
- **`ms_comparison_exact_simulation_equiv x s`** := equality of the surface clause distributions (= schedule equality).

**Constructor-image packaging (proved, non-crypto):** **`ms3c_real_clause_surface_in_constructor_image`** / **`ms3c_sim_clause_surface_in_constructor_image`** and membership lemmas from **`supp_dmap`** on the schedules.

## Obligation hooks (replaced `= true`; non-vacuous)

| Hook | Definition (summary) |
|------|----------------------|
| **`ms3c_comparison_query_digest_ann_only`** | For all simulatable `c`, **`ms3c_ann_digest_list_shape c`** (scheduling hook; list arity is also **proved** for all `c` via **`L_ms3c_ann_digest_list_shape`**). |
| **`ms3c_comparison_global_programmable_under_A2`** | **`ms3c_programmed_comparison_rom_ready`** := `forall qd, exists t, ms_query_to_scalar qd = t` (comparison ROM row). |
| **`ms3c_false_clauses_simulator_generated`** | **Existential**: some simulatable `c` with **`0 < size ann_false`** (nontrivial false-clause width). |
| **`ms3c_true_clause_schnorr_from_blinder`** | Conjunction hook: **`ms3c_true_clause_uses_ms3b_blinder_point`** + **`ms3c_true_clause_reparam_ready`** + position-from-simulation packaging. |
| **`ms3c_clause_challenge_shares_sum`** | **forall** simulatable `c`: **`mscc_programmed_challenge = mscc_global_challenge`**. |

**Structural packaging:** **`ms3c_clause_shares_sum_matches_global c`** is **`mscc_programmed_challenge = mscc_global_challenge`** (not `true`).

## Payload-level structure (`ms/comparison/*.ec`)

Support and pairing:

- **`ms3c_real_payload_on_support`** / **`ms3c_sim_payload_on_support`** — membership in **`d_ms3c_{real,sim}_comparison_payload`**.
- **`ms3c_payload_length_index_shapes_ok`** — nonneg true-clause index and matching lengths of false-announcement / false-share / false-index lists (equivalent to **`ms_comparison_clause_simulatable (ms3c_make_clause_surface p)`**).
- **`ms3c_false_clauses_payload_schedule_nontrivial`** — some on-support real or sim payload has **`0 < size mscp_ann_false`** (support-local counterpart to the global existential hook).
- **`ms3c_payload_pair_public_fields_match`** — indices, announcements, query / global / programmed digests align across a real/sim payload pair on support.
- **`ms3c_payload_pair_challenge_shares_match`** — true/false share vectors align across the pair.
- **`ms3c_payload_ann_digest_list_shape_ok`** — **`ms3c_ann_digest_list_shape (ms3c_make_clause_surface p)`** (announcement-shape on the folded surface).
- **`ms3c_payload_programmed_challenge_matches_global`** — **`ms3c_clause_shares_sum_matches_global (ms3c_make_clause_surface p)`** (challenge-share consistency).

Bundled obligation predicates (inputs to the payload scheduling coupling layer):

- **`ms3c_ax_payload_public_fields_match`**, **`ms3c_ax_payload_challenge_shares_match`**, **`ms3c_ax_payload_challenge_share_consistency`**, **`ms3c_ax_payload_false_clauses_simulated`**, **`ms3c_ax_payload_true_clause_simulated`** — these five are the explicit antecedents of the **proved** lemma **`A_ms3c_coupling_pair_relation`** (`ComparisonCouplingSchedule.ec`).
- **`ms3c_ax_payload_announcements_match_shape`** — still a named predicate (support-flavoured statement), but **unconditionally provable**: lemma **`L_ms3c_ax_payload_announcements_match_shape_total`** (`ComparisonPayloadSupport.ec`) from **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`** / **`L_ms3c_ann_digest_list_shape`** on folded surfaces. It is **not** a premise of **`A_ms3c_coupling_pair_relation`** anymore.
- **`ms3c_ax_payload_announcement_digests_preserved`** — still a named predicate, but **proved from** **`ms3c_ax_payload_public_fields_match`** by **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** (`ComparisonCouplingSchedule.ec`); **not** a premise of **`A_ms3c_coupling_pair_relation`** anymore.

## What `MS_3c_exact_comparison_simulation_from_clauses` consumes

Proof path:

1. **`A_ms3c_payload_schedule_equiv`** — **proved lemma**: five hooks ⇒ payload law equality, via **`A_ms3c_payload_support_coupling_from_components`** (packages **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** + **`A_ms3c_coupling_pair_relation`** into **`ms3c_ax_payload_support_coupling`**; payload-law losslessness comes from **`dmap_ll`** and **`L_ms3c_{real,sim}_payload_seed_lossless`** in **`ComparisonPayloadSeeds.ec`** (seed law = product of component samplers; **`L_ms3c_*_payload_seed_lossless`** from **`dprod_ll_auto`** and four component axioms); marginals use the **product** definition of **`d_ms3c_real_sim_payload_coupling`** (**`ComparisonCouplingMarginals.ec`**); unconditional announcement-shape from **`L_ms3c_ax_payload_announcements_match_shape_total`**; **`A_ms3c_coupling_pair_relation`** no longer lists **`ms3c_ax_payload_announcement_digests_preserved`**—when needed it follows from **`ms3c_ax_payload_public_fields_match`** via **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** and the **proved** lemma **`A_ms3c_payload_schedule_eq_from_coupling`** (below), plus the bridge lemmas.
2. **`A_ms3c_comparison_schedule_equiv`** — **proved lemma**: payload equality + **`qssm_dmap_congr`** (`ms/BitnessOne.ec`) with shared **`ms3c_make_clause_surface`**.
3. **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** — rewrites surface clause operators to schedules and closes **`ms_comparison_exact_simulation_equiv`**.
4. **`L_ms3c_rom_scalar_response_for_any_digest`** — unpacks **`Ha2`** (ROM / A2 surface).

**Hook → component bridges (proved):** **`L_ms3c_ax_payload_announcements_match_shape_total`** (unconditional; **`L_ms3c_ann_digest_list_shape`** on folded surfaces). Legacy wrapper **`L_ms3c_payload_announcements_match_shape_from_ann_hook`** delegates to that total lemma (prior simulatable-support premises were unused). **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** (announcement digest lists agree on joint support from public-field alignment). **`L_ms3c_payload_challenge_share_consistency_from_sum_hook`**, **`L_ms3c_payload_true_clause_simulated_from_true_hook`**.

**`MS_3c_comparison_clause_obligations`** still packages digest / false / true / share obligations; the false branch is **payload-support** shaped (real and sim marginals), discharged via the proved lemmas **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** and **`A_ms3c_false_clause_simulation`**. Their narrowing obligations are constructor-level false-index nonemptiness (**`A_ms3c_real_constructor_false_index_nonempty`**, **`A_ms3c_sim_constructor_false_index_nonempty`**) with seed-level wrappers (**`A_ms3c_real_seed_false_index_nonempty`**, **`A_ms3c_sim_seed_false_index_nonempty`**) plus existing seed index-shape equalities (to derive ann-list nonemptiness), and support-local generation (**`A_ms3c_false_clause_generation_on_support`**). The digest branch states programmed query digest vs **`ms3c_clause_ann_digests_from_surface`** via **`L_ms3c_digest_announcement_only`** (packaging over lemma **`A_ms3c_query_digest_statement_bound`**, i.e. axiom **`A_ms3c_surface_query_digest_field_correct`**; the proved alias **`L_ms3c_query_digest_uses_ann_digest_projection`** mirrors that fact; the **`Hann`** hook is redundant with **`L_ms3c_ann_digest_list_shape`**). Ordered announcement material is separated as **`L_ms3c_query_digest_ordered_announcements_bound`** (definitional from **`L_ms3c_ann_digest_projection_correct`**). Same-announcement ⇒ same programmed query digest is the **proved** corollary **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`**. Definitional ann projection facts are **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** (no separate **`ms_comparison_programmed_fs_consistent`** premise in that bundle).

## Axioms vs lemmas (remaining proof debt)

| Name | Kind | Conclusion shape |
|------|------|-------------------|
| **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** | **lemma** | **`ms3c_clause_ann_digests_from_surface`** equals the true-cons-then-mapped-false digest list; **`ms3c_clause_ann_digests`** alias. |
| **`A_ms3c_surface_query_digest_field_correct`** | **axiom** | Simulatable ⇒ **`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c)`** — constructor/wiring obligation (**`ms_comparison_query_digest`** in **`primitives/FS.ec`** = **`hash_domain LABEL_MS_V2_COMPARISON_QUERY (stmt :: ann_digests)`**). |
| **`A_ms3c_query_digest_statement_bound`** | **lemma** (`ComparisonDigests.ec`) | Same conclusion as **`A_ms3c_surface_query_digest_field_correct`** (backward-compatible name for callers). |
| **`L_ms3c_query_digest_uses_ann_digest_projection`** | **lemma** | Proved alias of **`A_ms3c_query_digest_statement_bound`** / **`A_ms3c_surface_query_digest_field_correct`**. |
| **`L_ms3c_query_digest_ordered_announcements_bound`** | **lemma** | On simulatable surfaces, **`ms3c_clause_ann_digests_from_surface c`** is **`ms3c_digest_true_announcement` of the true announcement** consed with **`ms3c_digest_false_announcements` of the false-announcement list** (**`L_ms3c_ann_digest_projection_correct`**). |
| **`L_ms3c_query_digest_statement_bound_hash`** | **lemma** | Expands **`ms_comparison_query_digest`** to the ROM **`hash_domain`** form. |
| **`L_ms3c_query_digest_no_witness_fields`** | **lemma** | Same **`stmt`** and announcement fields on two simulatable surfaces ⇒ same **`mscc_query_digest`**. |
| **`L_ms3c_query_digest_excludes_witness_fields`** | **lemma** | Same as **`L_ms3c_query_digest_no_witness_fields`** with **`stmt := ms3c_comparison_stmt_digest witness`**. |
| **`L_ms3c_digest_announcement_only`** | **lemma** | Legacy **`Hann` ⇒ …** packaging ( **`Hann`** discarded; conclusion from **`A_ms3c_query_digest_statement_bound`**). |
| **`L_ms3c_comparison_query_digest_ann_only_any`** | **lemma** | **`ms3c_comparison_query_digest_ann_only x s`** for all **`x`**, **`s`** (from **`L_ms3c_ann_digest_list_shape`**). |
| **`L_ms3c_ann_digest_list_shape`** | **lemma** | **`ms3c_ann_digest_list_shape c`** for all comparison surfaces `c`. |
| **`A_ms3c_real_constructor_false_index_nonempty`** / **`A_ms3c_sim_constructor_false_index_nonempty`** | axiom | Constructor-level nonemptiness of false-index list for every seed input. |
| **`A_ms3c_real_seed_false_index_nonempty`** / **`A_ms3c_sim_seed_false_index_nonempty`** | **lemma** | Seed-level wrappers of constructor nonemptiness obligations. |
| **`A_ms3c_real_seed_false_clause_nonempty`** / **`A_ms3c_sim_seed_false_clause_nonempty`** | **lemma** | Derived from false-index nonemptiness + seed index-shape equality (`size ann_false = size false_clause_ixs`). |
| **`A_ms3c_false_clause_generation_on_support`** | axiom | Support-local false-clause simulation bundle (**`ms3c_ax_payload_false_clauses_simulated`**). |
| **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** | **lemma** | Global hook implies schedule nontriviality (proved using real-seed nonemptiness + seed support witness from losslessness). |
| **`A_ms3c_false_clause_simulation`** | **lemma** | Packaging lemma from support-local generation to **`ms3c_ax_payload_false_clauses_simulated`**. |
| **`L_ms3c_true_clause_schnorr_equiv_from_ms3a`** | **lemma** | Discharges **`ms3c_true_clause_schnorr_equiv`** from **`MS_3a_single_branch_schnorr_reparam`**. |
| **`A_ms3c_true_clause_from_ms3b_and_schnorr`** | **lemma** | Consumes `Htrue` components; uses **`MS_3b_true_clause_characterization`** (+ reparam-readiness witness) to derive **`ms_clause_public_point_matches_blinder`**. |
| **`A_ms3c_challenge_share_sum`** | **lemma** | Share/global alignment hook ⇒ **`ms_comparison_challenges_split`**. |
| **`A_ms3c_real_seed_length_shape_valid`**, **`A_ms3c_real_seed_index_shape_valid`**, **`A_ms3c_sim_seed_length_shape_valid`**, **`A_ms3c_sim_seed_index_shape_valid`** | axiom (×4) | Seed-to-payload shape invariants; should follow from concrete **`ms3c_*_payload_from_seed`** (see **`ComparisonPayloadSeeds.ec`** comment block). **No proof** while **`from_seed`** is abstract. |
| **`A_ms3c_{real,sim}_payload_support_length_index_shapes`** | **lemma** | On-support payloads satisfy **`ms3c_payload_length_index_shapes_ok`**, proved from `supp_dmap` + the four seed-shape axioms. |
| **`L_ms3c_{real,sim}_payload_support_simulatable`** | **lemma** | From support length/index lemmas ⇒ folded surface **`ms_comparison_clause_simulatable`**. |
| **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`** / **`L_ms3c_{real,sim}_payload_on_support_ann_shape`** | **lemma** | Announcement digest list shape on payloads (**`L_ms3c_ann_digest_list_shape`**); no extra axioms. |
| **`A_ms3c_payload_index_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_index_fields_match`** (clause indices agree on cross-support pairs). |
| **`A_ms3c_payload_ann_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_ann_fields_match`** (true/false announcement points agree). |
| **`A_ms3c_payload_stmt_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_stmt_fields_match`** (**`mscp_query_digest`** agreement — programmed query digest / statement-hash side of the carrier). |
| **`A_ms3c_payload_result_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_result_fields_match`** (**`mscp_global_challenge`** and **`mscp_programmed_challenge`** agreement). |
| **`L_ms3c_ax_payload_public_fields_match_from_fragments`** | **lemma** (`ComparisonPayloadSupport.ec`) | The four **`ms3c_ax_payload_{index,ann,stmt,result}_fields_match`** predicates ⇒ **`ms3c_ax_payload_public_fields_match`**. |
| **`A_ms3c_payload_public_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Five hooks ⇒ **`ms3c_ax_payload_public_fields_match`** (packages the four field-level axioms via **`L_ms3c_ax_payload_public_fields_match_from_fragments`**). |
| **`A_ms3c_payload_true_challenge_share_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_true_challenge_share_match`** (**`mscp_share_true`** agreement on cross-support pairs). |
| **`A_ms3c_payload_false_challenge_shares_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_false_challenge_shares_match`** (**`mscp_share_false`** list agreement). |
| **`A_ms3c_payload_challenge_share_lengths_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_challenge_share_lengths_match`** (**`size mscp_share_false`** agreement; redundant given full false-list equality but kept for incremental discharge). |
| **`L_ms3c_ax_payload_challenge_shares_match_from_fragments`** | **lemma** (`ComparisonPayloadSupport.ec`) | True + false + length **`ms3c_ax_payload_*`** fragments ⇒ **`ms3c_ax_payload_challenge_shares_match`** (proof uses true + false list equality only). |
| **`A_ms3c_payload_challenge_shares_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Five hooks ⇒ **`ms3c_ax_payload_challenge_shares_match`** (packages the three share-level axioms via **`L_ms3c_ax_payload_challenge_shares_match_from_fragments`**). |
| **`ms3c_real_sim_payload_coupled`** / **`ms3c_ax_payload_coupling_pair_relation`** / **`ms3c_ax_payload_support_coupling`** | predicate | Pairwise payload coupling, pair-relation on support, and bundled support-coupling predicate. |
| **`d_ms3c_real_sim_payload_coupling`** | **definition** | **Independent product** **`d_ms3c_real_comparison_payload x `*` d_ms3c_sim_comparison_payload x s`** (`ComparisonCouplingTypes.ec`). |
| **`d_ms3c_coupling_{real,sim}_projection`** | operator | Marginals: **`dmap`** of the joint law through **`fst`** / **`snd`**. |
| **`d_ms3c_{real,sim}_seed_{challenge,announcement}`**, **`d_ms3c_{real,sim}_payload_seed`**, **`ms3c_{real,sim}_payload_from_seed`** | operator | Real/sim payload seed is a **pair** (challenge material `*` announcement material); joint seed law = **independent product** of the two component laws; **`d_ms3c_{real,sim}_comparison_payload`** = **`dmap`** pushforward (`ComparisonPayloadSeeds.ec`). **`d_ms3c_real_seed_challenge`** and **`d_ms3c_sim_seed_challenge`** are **`dunit tt`** on **`unit`**; the two announcement component laws and both **`from_seed`** maps remain abstract—see **`ComparisonPayloadSeeds.ec`**. |
| **`L_ms3c_real_seed_challenge_lossless`** | **lemma** (`ComparisonPayloadSeeds.ec`) | **`d_ms3c_real_seed_challenge`** is **`dunit tt`** on **`ms3c_real_seed_challenge = unit`** (Phase-1 scaffolding until FS challenge material is modeled). |
| **`L_ms3c_sim_seed_challenge_lossless`** | **lemma** (`ComparisonPayloadSeeds.ec`) | **`d_ms3c_sim_seed_challenge`** is **`dunit tt`** on **`ms3c_sim_seed_challenge = unit`** (Phase-1 scaffolding; not the final sim ROM or FS challenge sampler). |
| **`A_ms3c_{real,sim}_seed_announcement_lossless`** (remaining) | axiom (×2) | **`d_ms3c_real_seed_announcement`**, **`d_ms3c_sim_seed_announcement`** still abstract; each should become **`is_lossless`** from concrete definitions (**`duniform_ll`**, ROM products, etc.). |
| **`L_ms3c_real_payload_seed_lossless`** / **`L_ms3c_sim_payload_seed_lossless`** | **lemma** (`ComparisonPayloadSeeds.ec`) | **`dprod_ll_auto`** combines the two component losslessness facts per side. |
| **`L_ms3c_real_comparison_payload_law_lossless`** / **`L_ms3c_sim_comparison_payload_law_lossless`** | **lemma** (`ComparisonPayloadSeeds.ec`) | **`dmap_ll`** + **`L_ms3c_*_payload_seed_lossless`** ⇒ payload laws lossless (enables **`dprod_marginalL`** / **`dprod_marginalR`**). |
| **`L_dmap_dprod_fst_lossless`** / **`L_dmap_dprod_snd_lossless`** | **lemma** (`ComparisonCouplingMarginals.ec`) | Generic: lossless opposite side ⇒ **`dmap (da `*` db) fst = da`** (resp. **`snd = db`**). |
| **`L_ms3c_coupling_real_projection_eq_payload`** / **`L_ms3c_coupling_sim_projection_eq_payload`** | **lemma** (`ComparisonCouplingMarginals.ec`) | Sim (resp. real) law lossless ⇒ **`d_ms3c_coupling_{real,sim}_projection`** equals the corresponding standalone payload law (**product coupling**). |
| **`L_ms3c_coupling_real_marginal_eq`** / **`L_ms3c_coupling_sim_marginal_eq`** | **lemma** (`ComparisonCouplingMarginals.ec`) | **`eq_distr`** packaging from support-iff + pointwise **`mu1`** on support (**`contra`** + **`L_mu1_eq0_of_nmem`** off-support); used inside **`A_ms3c_payload_support_coupling_from_components`** once projection equalities are rewritten in. |
| **`L_ms3c_ax_payload_announcements_match_shape_total`** | **lemma** (`ComparisonPayloadSupport.ec`) | **`ms3c_ax_payload_announcements_match_shape x s`** for all **`x`**, **`s`** (from **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`**). |
| **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** | **lemma** (`ComparisonCouplingSchedule.ec`) | **`ms3c_ax_payload_public_fields_match`** ⇒ **`ms3c_ax_payload_announcement_digests_preserved`** (equal announcement points ⇒ equal **`ms3c_clause_ann_digests_from_surface`** lists). |
| **`A_ms3c_coupling_pair_relation`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Five facts (**`ms3c_ax_payload_public_fields_match`**, **`ms3c_ax_payload_challenge_shares_match`**, **`ms3c_ax_payload_challenge_share_consistency`**, **`ms3c_ax_payload_false_clauses_simulated`**, **`ms3c_ax_payload_true_clause_simulated`**) ⇒ **`ms3c_ax_payload_coupling_pair_relation`**. Only **`public_fields`**, **`challenge_shares`**, and **`false_clauses_simulated`** are used in the proof (via **`supp_dprod`** + digest list equality from public fields); **`challenge_share_consistency`** and **`true_clause_simulated`** are unused legacy premises kept for a stable statement shape. |
| **`L_ms3c_coupling_fst_snd_eq_from_pair_relation`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Pair relation ⇒ `d_ms3c_coupling_real_projection = d_ms3c_coupling_sim_projection` (**`eq_dmap_in`** + **`L_ms3c_payload_eq_of_coupled`**: on support, coupled payloads are equal, so `fst` and `snd` agree). |
| **`A_ms3c_payload_support_coupling_from_components`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Lossless laws + **`A_ms3c_coupling_pair_relation`** ⇒ **`ms3c_ax_payload_support_coupling`** (five component inputs; marginals proved from **`Distr`**). |
| **`A_ms3c_payload_schedule_eq_from_coupling`** | **lemma** (`ComparisonCouplingSchedule.ec`) | **`ms3c_ax_payload_support_coupling`** ⇒ `d_ms3c_real_comparison_payload = d_ms3c_sim_comparison_payload` (transitivity: real marginal + projection equality + sim marginal). |
| **`A_ms3c_payload_schedule_equiv`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Five hooks ⇒ payload law equality (components + schedule axiom). |
| **`A_ms3c_comparison_schedule_equiv`** | **lemma** | Five hooks ⇒ **schedule** equality (`dmap` congruence from payload lemma). |
| **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** | lemma | Schedule equality ⇒ **`ms_comparison_exact_simulation_equiv`**. |
| **`MS_3c_comparison_clause_obligations`** | lemma | Bundles digest / false / true / share obligations. |
| **`L_ms3c_rom_scalar_response_for_any_digest`** | lemma | **`Ha2`** ⇒ pointwise ROM responses. |

**Still open:** instantiate the two announcement component samplers (**`d_ms3c_real_seed_announcement`**, **`d_ms3c_sim_seed_announcement`**) and **`ms3c_{real,sim}_payload_from_seed`** from transcript / game material (**`d_ms3c_{real,sim}_seed_challenge`** are already **`dunit tt`** with proved **`L_ms3c_{real,sim}_seed_challenge_lossless`**); **prove** the two remaining **`A_ms3c_*_seed_announcement_lossless`** facts from concrete lossless draws (e.g. **`duniform`** / ROM products). Per-point announcement hashing (**`ms_single_bit_branch_digest`**). **`A_ms3c_coupling_pair_relation`** is now a **proved lemma** (pointwise **`ms3c_real_sim_payload_coupled`** on **`d_ms3c_real_sim_payload_coupling`** support follows from the five **`ms3c_ax_payload_*`** predicates and **`supp_dprod`**); remaining coupling **proof debt** is the hook-to-**`ms3c_ax_payload_*`** bridges: four field-level public-carrier axioms packaged by proved lemma **`A_ms3c_payload_public_fields_match`**; three share-level axioms (**`A_ms3c_payload_true_challenge_share_match`**, **`A_ms3c_payload_false_challenge_shares_match`**, **`A_ms3c_payload_challenge_share_lengths_match`**) packaged by proved lemma **`A_ms3c_payload_challenge_shares_match`**; plus false/true clause packaging. Also: support-shape bridge lemmas (**`A_ms3c_{real,sim}_payload_support_length_index_shapes`**) and their four seed-shape axioms, the false-clause narrowing axioms (**`A_ms3c_{real,sim}_seed_false_index_nonempty`**, **`A_ms3c_false_clause_generation_on_support`**), **`A_ms3c_surface_query_digest_field_correct`** (query digest field = ROM hash on statement + ordered announcement digests; lemma **`A_ms3c_query_digest_statement_bound`** is the same fact), and the MS-3b/reparam packaging hooks (**`ms3c_true_clause_uses_ms3b_blinder_point`**, **`ms3c_true_clause_reparam_ready`**) from the game. **`A_ms3c_payload_schedule_eq_from_coupling`** remains a **proved** lemma: it follows from **`ms3c_ax_payload_support_coupling`** once the packaged equalities hold.

## Concrete MS-3c payload constructor design (architecture)

This section is a **design-only** blueprint to discharge the **19** remaining **`A_ms3c_*`** axioms in **`ms/comparison/`** without changing existing **theorem statements** (only definitions and proofs behind abstract ops). It aligns **`ComparisonPayloadTypes.ec`**, **`ComparisonPayloadSeeds.ec`**, and later **game hops** with **`ms_transcript_observable`** / **`ms_v2_transcript_observable`** (`ms/TranscriptObservable.ec`, `ms/SourceModel.ec`).

### 1. Seed carriers (replace abstract types)

**Goal:** make **`ms3c_real_seed_challenge`**, **`ms3c_real_seed_announcement`**, **`ms3c_sim_seed_challenge`**, **`ms3c_sim_seed_announcement`** concrete record or tuple types large enough to hold every **`mscp_*`** field that is **not** fixed deterministically from **`ms_public_input`** alone.

**Suggested split (conceptual):**

- **Challenge side (`*_seed_challenge`):** material that fixes comparison **indices**, **challenge digests** (**`mscp_global_challenge`**, **`mscp_programmed_challenge`**), and **scalar shares** (**`mscp_share_true`**, **`mscp_share_false`**) after FS / split logic—typically finite-domain draws or ROM-derived scalars/digests bounded by the MS comparison arity implied by **`x`** (needs a length discipline from **`ms_public_input`** or a separate arity field once **`ms_public_input`** is structured).

- **Announcement side (`*_seed_announcement`):** material that fixes **Schnorr announcement points** (**`mscp_ann_true`**, **`mscp_ann_false`**) and any auxiliary randomness for **simulated** false branches on the sim side; real side uses honest announcement construction, sim side uses simulator map from shares (per **`ms_false_clause_simulated`**).

**Real vs sim:** types may **coincide** structurally (same tuple shape) with different **`d_ms3c_*`** laws, or differ if sim packs extra simulator coins; the abstract API already separates real vs sim theory names.

### 2. **`ms3c_real_payload_from_seed` / `ms3c_sim_payload_from_seed`**

Define both as **total** functions **`ms_public_input` → seed → `ms3c_comparison_clause_payload`**, assembling the canonical payload record:

1. **Indices** **`mscp_true_clause_ix`**, **`mscp_false_clause_ixs`:** from challenge seed (or from **`x`** if fixed by statement); must satisfy **`0 <= true_ix`** and list length consistency for **`A_ms3c_*_seed_index_shape_valid`** and **`A_ms3c_{real,sim}_constructor_false_index_nonempty`** (nonempty false list when comparison is nontrivial).

2. **Shares** **`mscp_share_true`**, **`mscp_share_false`:** from challenge seed; lengths must match **`mscp_false_clause_ixs`** / **`mscp_ann_false`** arity.

3. **Announcements** **`mscp_ann_true`**, **`mscp_ann_false`:** from announcement seed (real: honest openings; sim: **`sch_pubkey`** of false shares entrywise for **`ms_false_clause_simulated`** on support).

4. **Digests** **`mscp_global_challenge`**, **`mscp_programmed_challenge`:** from challenge seed; enforce **`mscp_programmed_challenge = mscp_global_challenge`** on all seeds if the hook **`ms3c_clause_challenge_shares_sum`** is to be discharged by construction.

5. **Query digest** **`mscp_query_digest`:** set **after** announcement points are fixed, as  
   **`ms_comparison_query_digest stmt ann_digests`**  
   where **`stmt`** is the comparison statement digest tied to **`x`** (today **`ms3c_comparison_stmt_digest x`** is **`witness`**—must be aligned with **`ms_statement_digest`** / **`msv2_statement_digest`** path via **`ms/SourceModel.ec`** and transcript bridges), and **`ann_digests`** is **`ms3c_clause_ann_digests_from_surface`** applied to the **folded** surface built from the same payload (or built directly from the same announcement fields). This is exactly the obligation behind **`A_ms3c_surface_query_digest_field_correct`**.

### 3. Component distributions **`d_ms3c_*_seed_*`**

Define each as a **composition** of finitely many **`duniform`**, **`dunit`**, **`dmap`** of ROM query (lossless when the ROM read is lossless on its domain), and **independent products** where the spec samples independently. Then:

- **`A_ms3c_*_seed_*_lossless`:** real and sim challenge done (**`L_ms3c_{real,sim}_seed_challenge_lossless`**); remaining two announcement laws `by` **`duniform_ll`**, **`dmap_ll`**, **`dprod_ll_auto`** once defined.

**Dependency:** finite **`Finite`**/`enum` carriers or proved full-support for each draw; arity of false-branch lists must be fixed from **`x`** (or carried inside **`ms_public_input`**) so **`duniform`** domains are well-typed.

### 4. Coupling vs transcript spine (risk)

The abstract coupling law is the **independent product** of real and sim **marginal** payload laws. The **seven** public/share **fragment axioms** assert cross-marginal **field equality** for arbitrary **`(pr, ps)`** on joint support—something **not** forced by the product alone. **Transcript-level design:** if the **game** builds real and sim comparison payloads from the **same** observable slice **`ms_transcript_observable`** (or same coupling variable) by **deterministic** maps, then those equalities become **`supp_dmap` / preimage** lemmas rather than axioms. If the game truly uses **independent** RNG for the two sides, the abstract axioms remain the honest semantic interface.

**`games/GameViews.ec`** today uses **`witness`** for **`ms_transcript_observable`** in **`mk_ms_game_view`**—constructor work must eventually pass **real** **`obs`** per stage so **`from_seed`** (or a renamed pipeline) can read comparison fields.

### 5. Axiom → discharge map (target definitions)

| Axiom group | Discharged by (intended) |
|-------------|---------------------------|
| **Seed losslessness** | Real and sim **challenge** laws done (**`dunit`**); two **announcement** laws + standard lossless lemmas remain. |
| **Seed shape ×4** | **`ms3c_*_payload_from_seed`** definitions + list arithmetic on fixed arities from **`x`**. |
| **Public-field fragments ×4** | Same transcript spine or shared coupling map ⇒ pointwise equality of index / ann / stmt / result fields on joint support; or retained axioms if margins stay independent. |
| **Challenge-share fragments ×3** | Same; **`A_ms3c_payload_challenge_share_lengths_match`** may become definitional once false-list equality is proved. |
| **False-index nonempty ×2** | Constructor chooses **`0 < size false_clause_ixs`** whenever comparison hop is active; may need **`ms_public_input`** predicate “comparison nontrivial”. |
| **`A_ms3c_false_clause_generation_on_support`** | **`from_seed`** sim path sets **`ms_false_clause_simulated`** on all support payloads (sim announcements = **`sch_pubkey`** of shares). |
| **`A_ms3c_surface_query_digest_field_correct`** | **`mscp_query_digest`** assigned as **`ms_comparison_query_digest stmt (…ann digests…)`** with **`stmt`** matching ROM programming; proof via **`/=`** + **`L_ms3c_ann_digest_projection_correct`** once **`stmt`** is the programmed statement digest. |

### 6. Dependency risks

| Risk | Mitigation |
|------|------------|
| **`ms_transcript_observable`** abstract | Use **`ms/SourceModel.ec`** accessors (**`ms_statement_digest`**, **`ms_comparison_global_challenge`**, …) and **`ms_v2_transcript_observable`** refinements; add **`ms3c_observable_comparison_slice`** bridge ops or refine **`ms_public_input`** to carry statement + arity. |
| **`ms_public_input`** abstract | Need digest arity / clause count for **`duniform`** domains; may require **`ms_public_input`** refinement or side conditions on games. |
| **Game view `witness` observable** | **`games/GameMSHop*.ec`** / **`GameViews.ec`**: thread **`obs`** through stages so comparison sampling can depend on frozen transcript fields. |
| **ROM / FS** | **`A_ms3c_surface_query_digest_field_correct`** and **`ms3c_clause_challenge_shares_sum`** tie to **`hash_domain`** / ROM programming lemmas (`primitives/FS.ec`, **`ms_query_to_scalar`** path). |

### 7. Recommended implementation sequence

1. **Smallest safe patch (comments + one witness reduction only if needed):** extend **`ComparisonPayloadSeeds.ec`** comment block with **arity source** for false lists (pointer to future **`ms_public_input`** refinement); **no** theorem statement changes.

2. **Types (`ComparisonPayloadTypes.ec`):** replace abstract seed types with concrete tuples (or records) documented in this plan; keep **`ms3c_*_payload_seed`** as product type.

3. **Constructors (`ComparisonPayloadSeeds.ec`):** define **`ms3c_real_payload_from_seed`**, **`ms3c_sim_payload_from_seed`**; define **`d_ms3c_*_seed_*`**; prove **`L_ms3c_*_payload_seed_lossless`** lemmas replace axioms; prove **shape** lemmas replace shape axioms.

4. **Digest (`ComparisonDigests.ec`):** prove **`A_ms3c_surface_query_digest_field_correct`** from constructor step (5) + **`ms_comparison_query_digest`** definition.

5. **False clause (`ComparisonPayloadFalseClause.ec`):** discharge constructor nonemptiness + **`A_ms3c_false_clause_generation_on_support`** from sim constructor + transcript invariants.

6. **Coupling axioms (`ComparisonCouplingAxioms.ec`):** replace fragment axioms with lemmas under **shared-spine** sampling theorem, **or** keep axioms until game coupling is modeled.

7. **Games:** replace **`witness`** **`obs`** with constructed observable; lemmas **`L_ms_game_view_*_mk`** pattern extend to real **`obs`**.

**Expected to remain axiomatic after first patch:** any property that is **true in the execution spec** but not forced by EasyCrypt definitions (e.g. ROM collision resistance, MS-3b operand hooks) should stay outside this constructor layer; the **first** patch should leave **all 19 axioms** until step 3 removes them in bulk.

## Next target

See **§ Concrete MS-3c payload constructor design** above: prefer **defining seed types + `from_seed` + component laws** before spending more proof effort on the seven cross-marginal fragment axioms in isolation. In parallel: thread **`ms_transcript_observable`** through **`games/GameViews.ec`** / hop modules; align **`ms3c_comparison_stmt_digest`** with transcript statement digest. Narrower incremental work (fragment axioms, digest axiom alone) remains valid if constructor work is blocked on **`ms_public_input`** structure.
