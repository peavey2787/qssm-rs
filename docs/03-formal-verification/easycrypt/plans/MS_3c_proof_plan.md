# MS-3c Proof Plan (EasyCrypt)

This note tracks **exact comparison-clause simulation** under programmed Fiat–Shamir. Definitions and the main skeleton lemma live in the split MS-3c modules under **`ms/comparison/*.ec`** (re-exported by **`ms/Comparison.ec`**); coupling logic is split across **`ComparisonCouplingTypes.ec`**, **`ComparisonCouplingAxioms.ec`**, **`ComparisonCouplingTheorem.ec`** with **`ComparisonCoupling.ec`** as a facade; **`ms/MS.ec`** exports the wrapper lemma **`MS_3c_exact_comparison_simulation`** (same proof as `MS_3c_exact_comparison_simulation_from_clauses` in `ms/comparison/ComparisonTheorem.ec`).

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

- **`ms3c_ax_payload_public_fields_match`**, **`ms3c_ax_payload_challenge_shares_match`**, **`ms3c_ax_payload_announcements_match_shape`**, **`ms3c_ax_payload_challenge_share_consistency`**, **`ms3c_ax_payload_false_clauses_simulated`**, **`ms3c_ax_payload_true_clause_simulated`**.

## What `MS_3c_exact_comparison_simulation_from_clauses` consumes

Proof path:

1. **`A_ms3c_payload_schedule_equiv`** — **proved lemma**: five hooks ⇒ payload law equality, via **`A_ms3c_payload_support_coupling_from_components`** (packages **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** + **`A_ms3c_coupling_pair_relation`** into **`ms3c_ax_payload_support_coupling`**; payload-law losslessness comes from **`dmap_ll`** and **`L_ms3c_{real,sim}_payload_seed_lossless`** in **`ComparisonPayloads.ec`** (seed law = product of component samplers; **`L_ms3c_*_payload_seed_lossless`** from **`dprod_ll_auto`** and four component axioms); marginals use the **product** definition of **`d_ms3c_real_sim_payload_coupling`**) and the **proved** lemma **`A_ms3c_payload_schedule_eq_from_coupling`** (below), plus the bridge lemmas.
2. **`A_ms3c_comparison_schedule_equiv`** — **proved lemma**: payload equality + **`qssm_dmap_congr`** (`ms/BitnessOne.ec`) with shared **`ms3c_make_clause_surface`**.
3. **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** — rewrites surface clause operators to schedules and closes **`ms_comparison_exact_simulation_equiv`**.
4. **`L_ms3c_rom_scalar_response_for_any_digest`** — unpacks **`Ha2`** (ROM / A2 surface).

**Hook → component bridges (proved):** **`L_ms3c_payload_announcements_match_shape_from_ann_hook`** (folded-surface simulatable support; uses **`L_ms3c_ann_digest_list_shape`**), **`L_ms3c_payload_challenge_share_consistency_from_sum_hook`**, **`L_ms3c_payload_true_clause_simulated_from_true_hook`**.

**`MS_3c_comparison_clause_obligations`** still packages digest / false / true / share obligations; the false branch is **payload-support** shaped (real and sim marginals), discharged via the proved lemmas **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** and **`A_ms3c_false_clause_simulation`**. Their narrowing obligations are constructor-level false-index nonemptiness (**`A_ms3c_real_constructor_false_index_nonempty`**, **`A_ms3c_sim_constructor_false_index_nonempty`**) with seed-level wrappers (**`A_ms3c_real_seed_false_index_nonempty`**, **`A_ms3c_sim_seed_false_index_nonempty`**) plus existing seed index-shape equalities (to derive ann-list nonemptiness), and support-local generation (**`A_ms3c_false_clause_generation_on_support`**). The digest branch states programmed query digest vs **`ms3c_clause_ann_digests_from_surface`** via **`L_ms3c_digest_announcement_only`** (packaging over **`A_ms3c_query_digest_statement_bound`**; the proved alias **`L_ms3c_query_digest_uses_ann_digest_projection`** is the old name’s meaning; the **`Hann`** hook is redundant with **`L_ms3c_ann_digest_list_shape`**). Ordered announcement material is separated as **`L_ms3c_query_digest_ordered_announcements_bound`** (definitional from **`L_ms3c_ann_digest_projection_correct`**). Same-announcement ⇒ same programmed query digest is the **proved** corollary **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`**. Definitional ann projection facts are **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** (no separate **`ms_comparison_programmed_fs_consistent`** premise in that bundle).

## Axioms vs lemmas (remaining proof debt)

| Name | Kind | Conclusion shape |
|------|------|-------------------|
| **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** | **lemma** | **`ms3c_clause_ann_digests_from_surface`** equals the true-cons-then-mapped-false digest list; **`ms3c_clause_ann_digests`** alias. |
| **`A_ms3c_query_digest_statement_bound`** | **axiom** | Simulatable ⇒ **`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c)`** (**`ms_comparison_query_digest`** in **`primitives/FS.ec`** = **`hash_domain LABEL_MS_V2_COMPARISON_QUERY (stmt :: ann_digests)`**; announcement-only list discipline). |
| **`L_ms3c_query_digest_uses_ann_digest_projection`** | **lemma** | Proved alias of **`A_ms3c_query_digest_statement_bound`** (replaces the former single axiom name). |
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
| **`A_ms3c_real_seed_length_shape_valid`**, **`A_ms3c_real_seed_index_shape_valid`**, **`A_ms3c_sim_seed_length_shape_valid`**, **`A_ms3c_sim_seed_index_shape_valid`** | axiom (×4) | Seed-to-payload constructors satisfy shape constraints (length matches and nonnegative true index + false-index arity). |
| **`A_ms3c_{real,sim}_payload_support_length_index_shapes`** | **lemma** | On-support payloads satisfy **`ms3c_payload_length_index_shapes_ok`**, proved from `supp_dmap` + the four seed-shape axioms. |
| **`L_ms3c_{real,sim}_payload_support_simulatable`** | **lemma** | From support length/index lemmas ⇒ folded surface **`ms_comparison_clause_simulatable`**. |
| **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`** / **`L_ms3c_{real,sim}_payload_on_support_ann_shape`** | **lemma** | Announcement digest list shape on payloads (**`L_ms3c_ann_digest_list_shape`**); no extra axioms. |
| **`A_ms3c_payload_public_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_public_fields_match`**. |
| **`A_ms3c_payload_challenge_shares_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_challenge_shares_match`**. |
| **`ms3c_real_sim_payload_coupled`** / **`ms3c_ax_payload_coupling_pair_relation`** / **`ms3c_ax_payload_support_coupling`** | predicate | Pairwise payload coupling, pair-relation on support, and bundled support-coupling predicate. |
| **`d_ms3c_real_sim_payload_coupling`** | **definition** | **Independent product** **`d_ms3c_real_comparison_payload x `*` d_ms3c_sim_comparison_payload x s`** (`ComparisonCouplingTypes.ec`). |
| **`d_ms3c_coupling_{real,sim}_projection`** | operator | Marginals: **`dmap`** of the joint law through **`fst`** / **`snd`**. |
| **`d_ms3c_{real,sim}_seed_{challenge,announcement}`**, **`d_ms3c_{real,sim}_payload_seed`**, **`ms3c_{real,sim}_payload_from_seed`** | operator | Real/sim payload seed is a **pair** (challenge material `*` announcement material); joint seed law = **independent product** of the two component laws; **`d_ms3c_{real,sim}_comparison_payload`** = **`dmap`** pushforward (`ComparisonPayloads.ec`). |
| **`A_ms3c_{real,sim}_seed_{challenge,announcement}_lossless`** | axiom (×4) | Each abstract **component** sampler has weight 1 (scheduling hygiene until wired to games). |
| **`L_ms3c_real_payload_seed_lossless`** / **`L_ms3c_sim_payload_seed_lossless`** | **lemma** | **`dprod_ll_auto`** combines the two component losslessness facts per side. |
| **`L_ms3c_real_comparison_payload_law_lossless`** / **`L_ms3c_sim_comparison_payload_law_lossless`** | **lemma** | **`dmap_ll`** + **`L_ms3c_*_payload_seed_lossless`** ⇒ payload laws lossless (enables **`dprod_marginalL`** / **`dprod_marginalR`**). |
| **`L_dmap_dprod_fst_lossless`** / **`L_dmap_dprod_snd_lossless`** | **lemma** | Generic: lossless opposite side ⇒ **`dmap (da `*` db) fst = da`** (resp. **`snd = db`**). |
| **`L_ms3c_coupling_real_projection_eq_payload`** / **`L_ms3c_coupling_sim_projection_eq_payload`** | **lemma** | Sim (resp. real) law lossless ⇒ **`d_ms3c_coupling_{real,sim}_projection`** equals the corresponding standalone payload law (**product coupling**). |
| **`L_ms3c_coupling_real_marginal_eq`** / **`L_ms3c_coupling_sim_marginal_eq`** | **lemma** | **`eq_distr`** packaging from support-iff + pointwise **`mu1`** on support (**`contra`** + **`L_mu1_eq0_of_nmem`** off-support); used inside **`A_ms3c_payload_support_coupling_from_components`** once projection equalities are rewritten in. |
| **`A_ms3c_coupling_pair_relation`** | axiom | Components ⇒ **`ms3c_ax_payload_coupling_pair_relation`** (quantified only for **`(pr, ps)`** on the joint support; **not** implied by the independent product). |
| **`L_ms3c_coupling_fst_snd_eq_from_pair_relation`** | **lemma** | Pair relation ⇒ `d_ms3c_coupling_real_projection = d_ms3c_coupling_sim_projection` (**`eq_dmap_in`** + **`L_ms3c_payload_eq_of_coupled`**: on support, coupled payloads are equal, so `fst` and `snd` agree). |
| **`A_ms3c_payload_support_coupling_from_components`** | **lemma** | Lossless laws + pair axiom ⇒ **`ms3c_ax_payload_support_coupling`** (marginals proved from **`Distr`**, not separate marginal axioms). |
| **`A_ms3c_payload_schedule_eq_from_coupling`** | **lemma** | **`ms3c_ax_payload_support_coupling`** ⇒ `d_ms3c_real_comparison_payload = d_ms3c_sim_comparison_payload` (transitivity: real marginal + projection equality + sim marginal). |
| **`A_ms3c_payload_schedule_equiv`** | **lemma** | Five hooks ⇒ payload law equality (components + schedule axiom). |
| **`A_ms3c_comparison_schedule_equiv`** | **lemma** | Five hooks ⇒ **schedule** equality (`dmap` congruence from payload lemma). |
| **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** | lemma | Schedule equality ⇒ **`ms_comparison_exact_simulation_equiv`**. |
| **`MS_3c_comparison_clause_obligations`** | lemma | Bundles digest / false / true / share obligations. |
| **`L_ms3c_rom_scalar_response_for_any_digest`** | lemma | **`Ha2`** ⇒ pointwise ROM responses. |

**Still open:** instantiate the four component samplers **`d_ms3c_{real,sim}_seed_{challenge,announcement}`** and **`ms3c_{real,sim}_payload_from_seed`** from transcript / game material; **prove** the four **`A_ms3c_*_seed_*_lossless`** facts from concrete lossless draws (e.g. **`duniform`** / ROM products). Per-point announcement hashing (**`ms_single_bit_branch_digest`**). Discharge **`A_ms3c_coupling_pair_relation`** (semantic bridge: independent product does **not** imply **`ms3c_real_sim_payload_coupled`** on support). Plus the hook bridges **`A_ms3c_payload_public_fields_match`**, **`A_ms3c_payload_challenge_shares_match`**, the support-shape bridge lemmas (**`A_ms3c_{real,sim}_payload_support_length_index_shapes`**) and their four seed-shape axioms, the false-clause narrowing axioms (**`A_ms3c_{real,sim}_seed_false_index_nonempty`**, **`A_ms3c_false_clause_generation_on_support`**), **`A_ms3c_query_digest_statement_bound`** (query digest = ROM hash on statement + ordered announcement digests only), and the MS-3b/reparam packaging hooks (**`ms3c_true_clause_uses_ms3b_blinder_point`**, **`ms3c_true_clause_reparam_ready`**) from the game. **`A_ms3c_payload_schedule_eq_from_coupling`** remains a **proved** lemma: it follows from **`ms3c_ax_payload_support_coupling`** once the packaged equalities hold.

## Next target

Instantiate the **four** component samplers and **`ms3c_{real,sim}_payload_from_seed`**, then discharge the four **`A_ms3c_*_seed_*_lossless`** axioms from the game. In parallel: refine payload carriers if the execution spec diverges, add `dmap` preimage lemmas for obligation predicates on **support**, and/or wire the comparison marginal in **`games/Games.ec`** (G0→G1).
