# MS-3c Proof Plan (EasyCrypt)

This note tracks **exact comparison-clause simulation** under programmed Fiat–Shamir. The **`ms/comparison/*.ec`** tree is **axiom-free** (all former **`A_ms3c_*`** obligations there are **proved lemmata**), and the former MS-3c game-hop bridge **`A_MS3c_comparison_bundle_implies_game_pr_equality`** in **`games/GameMSHopTypes.ec`** is now also a **proved lemma**. The game layer now collapses **`MSGameStageAfterComparison`** and **`MSGameStageSim`** through **`ms3c_game_pr_stage`** in **`games/GameAdvantage.ec`** whenever the MS-3c implication bundle holds, so **`A_MS3c_canonical_comparison_exact_bound`** remains a **proved lemma** from **`Adv_def`** by definitional `game_pr` equality.

**MS-3b handoff status:** the phase-1 comparison carrier is now fed by a native comparison slice instead of digest-backed derivations. **`ms_public_input`** in **`ms/SourceTypes.ec`** carries **`mspi_comparison_slice : ms_comparison_slice`**, containing the true-clause index/opening and the full false-entry list `(index * opening)`. **`ms3b_phase1_comparison_carrier`** in **`ms/true_clause/TrueClauseTypes.ec`** still uses the one-bit **`mspi_result_bit`** lane, but now reads the true-clause index/opening from that native slice. **`ms3c_phase1_payload_from_public_input`** in **`ms/comparison/ComparisonPayloadFromSeed.ec`** reads both true and false announcements/shares from the same native comparison data, and **`ms_transcript_observable`** in **`primitives/QssmTypes.ec`** now carries **`msv2_comparison_openings : ms_comparison_openings`** so the public game observable can expose those openings directly. The old singleton false-branch/index placeholder and digest-derived comparison openings are gone.

## Current status snapshot

- **Checker:** **`./check_easycrypt`** passes across all 77 EasyCrypt theories.
- **Axiom count:** 37 total **`axiom`** declarations under **`docs/03-formal-verification/easycrypt`**.
- **Comparison carrier:** false-branch/index placeholder removed; **`mspi_comparison_slice`** now carries the real true opening plus the full false-entry slice.
- **Comparison observable:** announcements and shares are carried natively through **`msv2_comparison_openings`** and aligned to the phase-1 payload by **`L_ms3c_public_obs_payload_alignment`** in **`games/GameAdvantage.ec`** and its wrapper in **`games/GameMSHopTypes.ec`**.

### Current MS-3c assumption table

| Hook | Current definition / source | Status |
|------|-----------------------------|--------|
| **`ms3c_comparison_query_digest_ann_only`** | Announcement-only digest discipline on folded comparison surfaces. | **proved lemma** via **`L_ms3c_comparison_query_digest_ann_only_any`** / digest-shape lemmas. |
| **`ms3c_comparison_global_programmable_under_A2`** | **`ms3c_programmed_comparison_rom_ready`** (`forall qd, exists t, ms_query_to_scalar qd = t`). | remains the ROM/A2-side assumption hook. |
| **`ms3c_false_clauses_simulator_generated`** | **`ms3c_public_false_branch_nonempty x /\ ms3c_public_false_openings_simulated x`**. | now expressed directly over the native false-entry slice and native false openings. |
| **`ms3c_true_clause_schnorr_from_blinder`** | MS-3b true-clause carrier plus Schnorr reparameterization / blinder-point packaging. | unchanged high-level hook; now fed by the native true opening. |
| **`ms3c_clause_challenge_shares_sum`** | Programmed challenge equals global challenge on comparison surfaces. | unchanged packaging hook. |

Definitions and the main skeleton lemma live in the split MS-3c modules under **`ms/comparison/*.ec`** (re-exported by **`ms/Comparison.ec`**). **Payloads** split across **`ComparisonPayloadTypes.ec`**, **`ComparisonPayloadSeedTypes.ec`**, **`ComparisonPayloadFromSeed.ec`**, **`ComparisonPayloadSeedAnchors.ec`**, facade **`ComparisonPayloadSeeds.ec`**, **`ComparisonPayloadSupport{Types,Public,Shares}.ec`** (facade **`ComparisonPayloadSupport.ec`**), **`ComparisonPayloadFalseClause.ec`**, with **`ComparisonPayload.ec`** as a thin **`require export`** facade (imports still use theory **`ComparisonPayload`**). **Coupling** splits across **`ComparisonCouplingTypes.ec`**, **`ComparisonCouplingAxioms.ec`**, **`ComparisonCouplingMarginals.ec`**, **`ComparisonCouplingSchedule.ec`**, with **`ComparisonCouplingTheorem.ec`** and **`ComparisonCoupling.ec`** as facades. **`ms/MS.ec`** exports the wrapper lemma **`MS_3c_exact_comparison_simulation`** (same proof as `MS_3c_exact_comparison_simulation_from_clauses` in `ms/comparison/ComparisonTheorem.ec`).

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
| **`ms3c_false_clauses_simulator_generated`** | **Conjunctive native-slice hook**: **`ms3c_public_false_branch_nonempty x /\ ms3c_public_false_openings_simulated x`**. |
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
- **`ms3c_ax_payload_announcements_match_shape`** — still a named predicate (support-flavoured statement), but **unconditionally provable**: lemma **`L_ms3c_ax_payload_announcements_match_shape_total`** (`ComparisonPayloadSupportPublic.ec`) from **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`** / **`L_ms3c_ann_digest_list_shape`** on folded surfaces. It is **not** a premise of **`A_ms3c_coupling_pair_relation`** anymore.
- **`ms3c_ax_payload_announcement_digests_preserved`** — still a named predicate, but **proved from** **`ms3c_ax_payload_public_fields_match`** by **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** (`ComparisonCouplingSchedule.ec`); **not** a premise of **`A_ms3c_coupling_pair_relation`** anymore.

## What `MS_3c_exact_comparison_simulation_from_clauses` consumes

Proof path:

1. **`A_ms3c_payload_schedule_equiv`** — **proved lemma**: five hooks ⇒ payload law equality, via **`A_ms3c_payload_support_coupling_from_components`** (packages **`L_ms3c_{real,sim}_comparison_payload_law_lossless`** + **`A_ms3c_coupling_pair_relation`** into **`ms3c_ax_payload_support_coupling`**; payload-law losslessness comes from **`dmap_ll`** and **`L_ms3c_{real,sim}_payload_seed_lossless`** in **`ComparisonPayloadSeedTypes.ec`** (seed law = product of component samplers; **`L_ms3c_*_payload_seed_lossless`** from **`dprod_ll_auto`** and four component losslessness lemmata); marginals use the **product** definition of **`d_ms3c_real_sim_payload_coupling`** (**`ComparisonCouplingMarginals.ec`**); unconditional announcement-shape from **`L_ms3c_ax_payload_announcements_match_shape_total`**; **`A_ms3c_coupling_pair_relation`** no longer lists **`ms3c_ax_payload_announcement_digests_preserved`**—when needed it follows from **`ms3c_ax_payload_public_fields_match`** via **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** and the **proved** lemma **`A_ms3c_payload_schedule_eq_from_coupling`** (below), plus the bridge lemmas.
2. **`A_ms3c_comparison_schedule_equiv`** — **proved lemma**: payload equality + **`qssm_dmap_congr`** (`ms/BitnessOne.ec`) with shared **`ms3c_make_clause_surface`**.
3. **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** — rewrites surface clause operators to schedules and closes **`ms_comparison_exact_simulation_equiv`**.
4. **`L_ms3c_rom_scalar_response_for_any_digest`** — unpacks **`Ha2`** (ROM / A2 surface).

**Hook → component bridges (proved):** **`L_ms3c_ax_payload_announcements_match_shape_total`** (unconditional; **`L_ms3c_ann_digest_list_shape`** on folded surfaces). Legacy wrapper **`L_ms3c_payload_announcements_match_shape_from_ann_hook`** delegates to that total lemma (prior simulatable-support premises were unused). **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** (announcement digest lists agree on joint support from public-field alignment). **`L_ms3c_payload_challenge_share_consistency_from_sum_hook`**, **`L_ms3c_payload_true_clause_simulated_from_true_hook`**.

**`MS_3c_comparison_clause_obligations`** still packages digest / false / true / share obligations; the false branch is **payload-support** shaped (real and sim marginals), discharged via the proved lemmas **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** and **`A_ms3c_false_clause_simulation`**. Their narrowing obligations are constructor-level false-index nonemptiness (**`L_ms3c_{real,sim}_constructor_false_index_nonempty`**: **`ms3c_public_false_branch_nonempty x`**, public-index anchors, and **`ms3c_public_shape_ok`**) with seed-level wrappers (**`A_ms3c_{real,sim}_seed_false_index_nonempty`**) packaging the native false-clause hook **`ms3c_false_clauses_simulator_generated x s`**, the public-index anchors, and those constructor lemmas, then **index-shape lemmata** (**`L_ms3c_{real,sim}_seed_index_shape_valid`**) to derive ann-list nonemptiness, plus **`L_ms3c_false_clause_generation_on_support`** (proved from **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`**, now **lemmata** via **`L_ms3c_{real,sim}_payload_on_support_eq_phase1`** and **`L_ms_false_clause_simulated_phase1_from_public_input`** in **`ComparisonPayloadFromSeed.ec`** / **`ComparisonPayloadSupportTypes.ec`** / **`ComparisonPayloadFalseClause.ec`**). The digest branch states programmed query digest vs **`ms3c_clause_ann_digests_from_surface`** via **`L_ms3c_digest_announcement_only`** (packaging over lemma **`A_ms3c_query_digest_statement_bound`**, i.e. **`A_ms3c_surface_query_digest_field_correct`** from proved lemma **`A_ms3c_clause_surface_query_digest_constructed`** plus **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**; the proved alias **`L_ms3c_query_digest_uses_ann_digest_projection`** mirrors that fact; the **`Hann`** hook is redundant with **`L_ms3c_ann_digest_list_shape`**). Ordered announcement material is separated as **`L_ms3c_query_digest_ordered_announcements_bound`** (definitional from **`L_ms3c_ann_digest_projection_correct`**). Same-announcement ⇒ same programmed query digest is the **proved** corollary **`L_ms3c_query_digest_no_witness_fields`** / **`L_ms3c_query_digest_excludes_witness_fields`**. Definitional ann projection facts are **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** (no separate **`ms_comparison_programmed_fs_consistent`** premise in that bundle).

## Axioms vs lemmas (remaining proof debt)

| Name | Kind | Conclusion shape |
|------|------|-------------------|
| **`L_ms3c_ann_digest_projection_correct`** / **`L_ms3c_ann_digests_alias`** | **lemma** | **`ms3c_clause_ann_digests_from_surface`** equals the true-cons-then-mapped-false digest list; **`ms3c_clause_ann_digests`** alias. |
| **`A_ms3c_clause_surface_query_digest_constructed`** | **lemma** (`ComparisonDigests.ec`) | **`p = ms3c_phase1_payload_from_public_input x`** and simulatable surface ⇒ **`p.`mscp_query_digest = ms_comparison_query_digest (ms3c_public_stmt_digest x) (…)`**; proved by unfolding Phase-1 (**no `forall stmt`**). |
| **`A_ms3c_surface_query_digest_field_correct`** | **lemma** (`ComparisonDigests.ec`) | **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`** and simulatable **`c`** ⇒ ROM query digest equality with **`ms3c_public_stmt_digest x`**; uses **`A_ms3c_clause_surface_query_digest_constructed`**. |
| **`A_ms3c_query_digest_statement_bound`** | **lemma** (`ComparisonDigests.ec`) | Same **`x`**, **`c`**, and payload-link premise as **`A_ms3c_surface_query_digest_field_correct`**. |
| **`L_ms3c_query_digest_uses_ann_digest_projection`** | **lemma** | Proved alias of **`A_ms3c_query_digest_statement_bound`** / **`A_ms3c_surface_query_digest_field_correct`**. |
| **`L_ms3c_query_digest_ordered_announcements_bound`** | **lemma** | On simulatable surfaces, **`ms3c_clause_ann_digests_from_surface c`** is **`ms3c_digest_true_announcement` of the true announcement** consed with **`ms3c_digest_false_announcements` of the false-announcement list** (**`L_ms3c_ann_digest_projection_correct`**). |
| **`L_ms3c_query_digest_statement_bound_hash`** | **lemma** | Expands **`ms_comparison_query_digest`** to the ROM **`hash_domain`** form. |
| **`L_ms3c_query_digest_no_witness_fields`** | **lemma** | Same **`stmt`** and announcement fields on two simulatable surfaces ⇒ same **`mscc_query_digest`**. |
| **`L_ms3c_query_digest_excludes_witness_fields`** | **lemma** | Same as **`L_ms3c_query_digest_no_witness_fields`** with **`stmt := ms3c_comparison_stmt_digest witness`**. |
| **`L_ms3c_digest_announcement_only`** | **lemma** | Legacy **`Hann` ⇒ …** packaging ( **`Hann`** discarded; conclusion from **`A_ms3c_query_digest_statement_bound`**). |
| **`L_ms3c_comparison_query_digest_ann_only_any`** | **lemma** | **`ms3c_comparison_query_digest_ann_only x s`** for all **`x`**, **`s`** (from **`L_ms3c_ann_digest_list_shape`**). |
| **`L_ms3c_ann_digest_list_shape`** | **lemma** | **`ms3c_ann_digest_list_shape c`** for all comparison surfaces `c`. |
| **`ms3c_public_false_branch_nonempty`** | predicate (`ComparisonTypes.ec`) | **`0 < ms3c_public_false_branch_count x`** (public arity / nontriviality). |
| **`L_ms3c_public_shape_ok_of_native_slice`** | **lemma** (`ComparisonTypes.ec`) | The native comparison slice yields **`0 <= ms3c_public_true_clause_index x`** and **`size (ms3c_public_false_announcements x) = size (ms3c_public_false_clause_indices x)`**. |
| **`L_ms3c_real_constructor_false_index_nonempty`** / **`L_ms3c_sim_constructor_false_index_nonempty`** | **lemma** (`ComparisonPayloadFalseClause.ec`) | From **`ms3c_public_false_branch_nonempty x`**, public-index anchor, and **`ms3c_public_shape_ok`** (list length vs count). |
| **`A_ms3c_real_seed_false_index_nonempty`** / **`A_ms3c_sim_seed_false_index_nonempty`** | **lemma** | Instantiate constructor lemmas from **`ms3c_false_clauses_simulator_generated x s`** plus **`A_ms3c_{real,sim}_from_seed_uses_public_indices`**. |
| **`A_ms3c_real_seed_false_clause_nonempty`** / **`A_ms3c_sim_seed_false_clause_nonempty`** | **lemma** | Derived from false-index nonemptiness + seed index-shape equality (`size ann_false = size false_clause_ixs`). |
| **`A_ms3c_real_false_announcements_match_shares_on_support`** | **lemma** (`ComparisonPayloadFalseClause.ec`) | Real on-support payloads satisfy **`ms_false_clause_simulated`**: rewrite support to **`ms3c_phase1_payload_from_public_input x`**, then **`L_ms_false_clause_simulated_phase1_from_public_input`** (Phase-1 **`mscp_ann_false = map sch_pubkey mscp_share_false`**). |
| **`A_ms3c_sim_false_announcements_match_shares_on_support`** | **lemma** (`ComparisonPayloadFalseClause.ec`) | Same as real, using **`L_ms3c_sim_payload_on_support_eq_phase1`**. |
| **`L_ms3c_false_clause_generation_on_support`** | **lemma** (`ComparisonPayloadFalseClause.ec`) | **`ms3c_ax_payload_false_clauses_simulated`** from **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** (**proved lemmata** on payload support). |
| **`A_ms3c_false_clauses_hook_implies_schedule_nontrivial`** | **lemma** | Global hook implies schedule nontriviality (proved using real-seed nonemptiness + seed support witness from losslessness). |
| **`A_ms3c_false_clause_simulation`** | **lemma** | Packaging lemma from support-local generation to **`ms3c_ax_payload_false_clauses_simulated`**. |
| **`A_MS3c_comparison_bundle_implies_game_pr_equality`** | **lemma** (`games/GameMSHopTypes.ec`) | The MS-3c implication bundle (same shape as **`ms3c_comparison_exact_step`**) now implies **`game_pr (G_MS_after_comparison …) D = game_pr (G_MS_sim …) D`** by definitional stage collapse through **`ms3c_game_pr_stage`** in **`games/GameAdvantage.ec`**. |
| **`A_MS3c_canonical_comparison_exact_bound`** | **lemma** (`games/GameMSHopTypes.ec`) | Same bundle as the lemma above ⇒ **`Adv (G_MS_after_comparison …) (G_MS_sim …) D <= 0%r`**; proved from **`Adv_def`**, **`A_MS3c_comparison_bundle_implies_game_pr_equality`**, and **`ring`**. |
| **`L_ms3c_true_clause_schnorr_equiv_from_ms3a`** | **lemma** | Discharges **`ms3c_true_clause_schnorr_equiv`** from **`MS_3a_single_branch_schnorr_reparam`**. |
| **`A_ms3c_true_clause_from_ms3b_and_schnorr`** | **lemma** | Consumes `Htrue` components; uses **`MS_3b_true_clause_characterization`** (+ reparam-readiness witness) to derive **`ms_clause_public_point_matches_blinder`**. |
| **`A_ms3c_challenge_share_sum`** | **lemma** | Share/global alignment hook ⇒ **`ms_comparison_challenges_split`**. |
| **`A_ms3c_sim_from_seed_uses_share_length`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | **`ms3c_sim_from_seed_share_length_anchor`**: **`size mscp_share_false = size mscp_ann_false`** on sim **`from_seed`** payload (Phase-1 constructor: parallel **`map`** over **`ms3c_public_false_clause_indices x`**). |
| **`L_ms3c_sim_seed_length_shape_valid`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | From **`ms3c_sim_from_seed_share_length_anchor`** by symmetry of equality. |
| **`A_ms3c_real_from_seed_uses_share_length`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | **`ms3c_real_from_seed_share_length_anchor`**: **`size mscp_share_false = size mscp_ann_false`** on real **`from_seed`** payload (Phase-1 constructor). |
| **`L_ms3c_real_seed_length_shape_valid`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | From **`ms3c_real_from_seed_share_length_anchor`** by symmetry of equality. |
| **`A_ms3c_real_from_seed_uses_public_indices`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | **`ms3c_real_from_seed_public_index_anchor`**: real **`from_seed`** false-index list and true index match **`ms3c_public_*`**, and **`size mscp_ann_false = size mscp_false_clause_ixs`**. |
| **`A_ms3c_sim_from_seed_uses_public_indices`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | **`ms3c_sim_from_seed_public_index_anchor`**: same equalities for **`ms3c_sim_payload_from_seed x s ss`**. |
| **`L_ms3c_real_seed_index_shape_valid`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | From **`ms3c_real_from_seed_public_index_anchor`** + **`L_ms3c_public_shape_ok_of_native_slice`** for the native public true index and false-list shape. |
| **`L_ms3c_sim_seed_index_shape_valid`** | **lemma** (`ComparisonPayloadSeedAnchors.ec`) | Same pattern as real (**`ms3c_sim_from_seed_public_index_anchor`** + **`L_ms3c_public_shape_ok_of_native_slice`**). |
| **`A_ms3c_{real,sim}_payload_support_length_index_shapes`** | **lemma** (`ComparisonPayloadSupportTypes.ec`) | On-support payloads satisfy **`ms3c_payload_length_index_shapes_ok`**, proved from `supp_dmap` + both share-length lemmata + both public-index anchors (via index-shape lemmata). |
| **`L_ms3c_{real,sim}_payload_support_simulatable`** | **lemma** | From support length/index lemmas ⇒ folded surface **`ms_comparison_clause_simulatable`**. |
| **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`** / **`L_ms3c_{real,sim}_payload_on_support_ann_shape`** | **lemma** | Announcement digest list shape on payloads (**`L_ms3c_ann_digest_list_shape`**); no extra axioms. |
| **`L_ms3c_cross_support_real_sim_payload_equal`** | **lemma** (`ComparisonPayloadFromSeed.ec`) | On support, real and sim payloads are **`dmap`** preimages of the same Phase-1 **`ms3c_{real,sim}_payload_from_seed`** body ⇒ **`pr = ps`**. |
| **`A_ms3c_payload_index_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Five hooks ⇒ **`ms3c_ax_payload_index_fields_match`**; proved from **`L_ms3c_cross_support_real_sim_payload_equal`** (index fields are **reflexive** once **`pr = ps`**). |
| **`A_ms3c_payload_ann_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Same cross-support equality ⇒ announcement fields agree (Phase-1 still uses **`witness`** lists, but they are **identical** on both sides). |
| **`A_ms3c_payload_stmt_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Same as other public fragments: **`L_ms3c_cross_support_real_sim_payload_equal`** ⇒ **`mscp_query_digest`** agrees on cross-support pairs (Phase-1 shared payload). |
| **`A_ms3c_payload_result_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | From **`L_ms3c_cross_support_real_sim_payload_equal`** (result fields reflexive once **`pr = ps`**). |
| **`L_ms3c_ax_payload_public_fields_match_from_fragments`** | **lemma** (`ComparisonPayloadSupportPublic.ec`) | The four **`ms3c_ax_payload_{index,ann,stmt,result}_fields_match`** predicates ⇒ **`ms3c_ax_payload_public_fields_match`**. |
| **`A_ms3c_payload_public_fields_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Five hooks ⇒ **`ms3c_ax_payload_public_fields_match`** (packages four proved field fragments via **`L_ms3c_ax_payload_public_fields_match_from_fragments`**). |
| **`A_ms3c_payload_true_challenge_share_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | From **`L_ms3c_cross_support_real_sim_payload_equal`**. |
| **`A_ms3c_payload_false_challenge_shares_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | From **`L_ms3c_cross_support_real_sim_payload_equal`**. |
| **`A_ms3c_payload_challenge_share_lengths_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | From **`L_ms3c_cross_support_real_sim_payload_equal`** (**`size`** reflexive once lists agree via **`pr = ps`**). |
| **`L_ms3c_ax_payload_challenge_shares_match_from_fragments`** | **lemma** (`ComparisonPayloadSupportShares.ec`) | True + false + length **`ms3c_ax_payload_*`** fragments ⇒ **`ms3c_ax_payload_challenge_shares_match`** (proof uses true + false list equality only). |
| **`A_ms3c_payload_challenge_shares_match`** | **lemma** (`ComparisonCouplingAxioms.ec`) | Five hooks ⇒ **`ms3c_ax_payload_challenge_shares_match`** (packages three proved share fragments via **`L_ms3c_ax_payload_challenge_shares_match_from_fragments`**). |
| **`ms3c_real_sim_payload_coupled`** / **`ms3c_ax_payload_coupling_pair_relation`** / **`ms3c_ax_payload_support_coupling`** | predicate | Pairwise payload coupling, pair-relation on support, and bundled support-coupling predicate. |
| **`d_ms3c_real_sim_payload_coupling`** | **definition** | **Independent product** **`d_ms3c_real_comparison_payload x `*` d_ms3c_sim_comparison_payload x s`** (`ComparisonCouplingTypes.ec`). |
| **`d_ms3c_coupling_{real,sim}_projection`** | operator | Marginals: **`dmap`** of the joint law through **`fst`** / **`snd`**. |
| **`d_ms3c_{real,sim}_seed_{challenge,announcement}`**, **`d_ms3c_{real,sim}_payload_seed`**, **`ms3c_{real,sim}_payload_from_seed`** | operator | Real/sim payload seed is a **pair** (challenge material `*` announcement material); joint seed law = **independent product** of the two component laws (**`ComparisonPayloadSeedTypes.ec`**); **`d_ms3c_{real,sim}_comparison_payload`** = **`dmap`** pushforward (**`ComparisonPayloadFromSeed.ec`**). All four component seed laws are **`dunit tt`** on **`unit`** (Phase-1); **`from_seed`** is the shared **`ms3c_phase1_payload_from_public_input x`** (seeds ignored until richer samplers land). |
| **`L_ms3c_real_seed_challenge_lossless`** | **lemma** (`ComparisonPayloadSeedTypes.ec`) | **`d_ms3c_real_seed_challenge`** is **`dunit tt`** on **`ms3c_real_seed_challenge = unit`** (Phase-1 scaffolding until FS challenge material is modeled). |
| **`L_ms3c_sim_seed_challenge_lossless`** | **lemma** (`ComparisonPayloadSeedTypes.ec`) | **`d_ms3c_sim_seed_challenge`** is **`dunit tt`** on **`ms3c_sim_seed_challenge = unit`** (Phase-1 scaffolding; not the final sim ROM or FS challenge sampler). |
| **`L_ms3c_real_seed_announcement_lossless`** | **lemma** (`ComparisonPayloadSeedTypes.ec`) | **`d_ms3c_real_seed_announcement`** is **`dunit tt`** on **`ms3c_real_seed_announcement = unit`** (Phase-1 scaffolding; not the final semantic announcement or Schnorr sampler). |
| **`L_ms3c_sim_seed_announcement_lossless`** | **lemma** (`ComparisonPayloadSeedTypes.ec`) | **`d_ms3c_sim_seed_announcement`** is **`dunit tt`** on **`ms3c_sim_seed_announcement = unit`** (Phase-1 scaffolding; not the final semantic sim announcement or Schnorr sampler). |
| **`L_ms3c_real_payload_seed_lossless`** / **`L_ms3c_sim_payload_seed_lossless`** | **lemma** (`ComparisonPayloadSeedTypes.ec`) | **`dprod_ll_auto`** combines the two component losslessness facts per side. |
| **`L_ms3c_real_comparison_payload_law_lossless`** / **`L_ms3c_sim_comparison_payload_law_lossless`** | **lemma** (`ComparisonPayloadFromSeed.ec`) | **`dmap_ll`** + **`L_ms3c_*_payload_seed_lossless`** ⇒ payload laws lossless (enables **`dprod_marginalL`** / **`dprod_marginalR`**). |
| **`L_dmap_dprod_fst_lossless`** / **`L_dmap_dprod_snd_lossless`** | **lemma** (`ComparisonCouplingMarginals.ec`) | Generic: lossless opposite side ⇒ **`dmap (da `*` db) fst = da`** (resp. **`snd = db`**). |
| **`L_ms3c_coupling_real_projection_eq_payload`** / **`L_ms3c_coupling_sim_projection_eq_payload`** | **lemma** (`ComparisonCouplingMarginals.ec`) | Sim (resp. real) law lossless ⇒ **`d_ms3c_coupling_{real,sim}_projection`** equals the corresponding standalone payload law (**product coupling**). |
| **`L_ms3c_coupling_real_marginal_eq`** / **`L_ms3c_coupling_sim_marginal_eq`** | **lemma** (`ComparisonCouplingMarginals.ec`) | **`eq_distr`** packaging from support-iff + pointwise **`mu1`** on support (**`contra`** + **`L_mu1_eq0_of_nmem`** off-support); used inside **`A_ms3c_payload_support_coupling_from_components`** once projection equalities are rewritten in. |
| **`L_ms3c_ax_payload_announcements_match_shape_total`** | **lemma** (`ComparisonPayloadSupportPublic.ec`) | **`ms3c_ax_payload_announcements_match_shape x s`** for all **`x`**, **`s`** (from **`L_ms3c_{real,sim}_payload_ann_digest_list_shape_ok`**). |
| **`L_ms3c_payload_announcement_digests_preserved_from_public_fields`** | **lemma** (`ComparisonCouplingSchedule.ec`) | **`ms3c_ax_payload_public_fields_match`** ⇒ **`ms3c_ax_payload_announcement_digests_preserved`** (equal announcement points ⇒ equal **`ms3c_clause_ann_digests_from_surface`** lists). |
| **`A_ms3c_coupling_pair_relation`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Five facts (**`ms3c_ax_payload_public_fields_match`**, **`ms3c_ax_payload_challenge_shares_match`**, **`ms3c_ax_payload_challenge_share_consistency`**, **`ms3c_ax_payload_false_clauses_simulated`**, **`ms3c_ax_payload_true_clause_simulated`**) ⇒ **`ms3c_ax_payload_coupling_pair_relation`**. Only **`public_fields`**, **`challenge_shares`**, and **`false_clauses_simulated`** are used in the proof (via **`supp_dprod`** + digest list equality from public fields); **`challenge_share_consistency`** and **`true_clause_simulated`** are unused legacy premises kept for a stable statement shape. |
| **`L_ms3c_coupling_fst_snd_eq_from_pair_relation`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Pair relation ⇒ `d_ms3c_coupling_real_projection = d_ms3c_coupling_sim_projection` (**`eq_dmap_in`** + **`L_ms3c_payload_eq_of_coupled`**: on support, coupled payloads are equal, so `fst` and `snd` agree). |
| **`A_ms3c_payload_support_coupling_from_components`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Lossless laws + **`A_ms3c_coupling_pair_relation`** ⇒ **`ms3c_ax_payload_support_coupling`** (five component inputs; marginals proved from **`Distr`**). |
| **`A_ms3c_payload_schedule_eq_from_coupling`** | **lemma** (`ComparisonCouplingSchedule.ec`) | **`ms3c_ax_payload_support_coupling`** ⇒ `d_ms3c_real_comparison_payload = d_ms3c_sim_comparison_payload` (transitivity: real marginal + projection equality + sim marginal). |
| **`A_ms3c_payload_schedule_equiv`** | **lemma** (`ComparisonCouplingSchedule.ec`) | Five hooks ⇒ payload law equality (components + schedule axiom). |
| **`A_ms3c_comparison_schedule_equiv`** | **lemma** | Five hooks ⇒ **schedule** equality (`dmap` congruence from payload lemma). |
| **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** | lemma (`ComparisonPayloadSupportTypes.ec`) | Schedule equality ⇒ **`ms_comparison_exact_simulation_equiv`**. |
| **`MS_3c_comparison_clause_obligations`** | lemma | Bundles digest / false / true / share obligations. |
| **`L_ms3c_rom_scalar_response_for_any_digest`** | lemma | **`Ha2`** ⇒ pointwise ROM responses. |

**Still open:** Phase-1 comparison data is now native, but the seed laws are still skeletal. The next MS-3c work is to replace the current **`unit`** challenge/announcement seed carriers with transcript-sized or ROM-sized samplers and then enrich **`ms3c_{real,sim}_payload_from_seed`** without regressing the now-native comparison slice / observable alignment. The four **`A_ms3c_{real,sim}_from_seed_uses_*`** facts remain **proved lemmas** in **`ComparisonPayloadSeedAnchors.ec`**, all four component samplers are still **`dunit tt`** with proved losslessness lemmata, and **`ComparisonCouplingAxioms.ec`** still has **no** remaining fragment axioms. The remaining proof debt is therefore in richer seed / execution modeling, not in placeholder comparison carriers.

## MS public-input / transcript projection interface (current state)

**Current spine:** **`ms_public_input`** in **`ms/SourceTypes.ec`** now carries a native **`ms_comparison_slice`**, and **`ms_transcript_observable`** in **`primitives/QssmTypes.ec`** now carries native **`ms_comparison_openings`**. **`ms/SourceModel.ec`** exposes those fields through **`ms3a_public_comparison_slice`**, **`ms3a_public_comparison_openings`**, and **`ms3a_public_v2_observable`**, and the game layer routes **`ms_game_view_public_obs xms`** through that concrete observable path.

**What this phase changed:**

- **Public carrier:** **`mspi_comparison_slice`** now holds the real true-clause index/opening and the full false-entry list, so comparison width and false indices are no longer synthetic singleton placeholders.
- **Observable carrier:** **`msv2_comparison_openings`** now carries the true opening and the false-opening list natively; **`ms3c_obs_{share,ann}_*`** project from those openings instead of deriving from comparison or transcript digests.
- **Phase-1 payload:** **`ms3c_phase1_payload_from_public_input`** now fills **`mscp_true_clause_ix`**, **`mscp_false_clause_ixs`**, **`mscp_ann_true`**, **`mscp_ann_false`**, **`mscp_share_true`**, and **`mscp_share_false`** directly from the native comparison slice / openings.
- **False-clause hook:** **`ms3c_false_clauses_simulator_generated`** is now the native-slice condition **`ms3c_public_false_branch_nonempty x /\ ms3c_public_false_openings_simulated x`**.
- **Game-layer alignment:** **`L_ms3c_public_obs_payload_alignment`** and **`L_ms_MS3c_public_obs_matches_phase1_payload`** now prove that the phase-1 payload and the public game observable agree on programmed challenge, global challenge, true opening, and false-opening projections.

**Remaining design boundary:** the carrier plumbing is now native, but the seed samplers are still Phase-1 scaffolding. Future work is to replace the current **`unit`** challenge/announcement seed components with richer transcript or ROM samplers without reintroducing digest-derived comparison fields.

### Next **code** steps (after projection surface)

1. **Wire game views:** **`mk_ms_game_view`** / **`ms_*_transcript`** with real **`obs`** ( **`games/GameViews.ec`**, **`ms/MS.ec`** ), then optionally **`ms3c_comparison_stmt_digest x := ms3c_public_stmt_digest x`** or link to **`ms_statement_digest obs`**.
2. **Richer `from_seed`:** read **`ms3c_obs_*`**, **`ms_comparison_global_challenge obs`**, and (eventually) ROM-derived **`mscp_query_digest`** from transcript / games; the four **`A_ms3c_{real,sim}_from_seed_uses_*`** lemmas already hold for the Phase-1 **`ms3c_phase1_payload_from_public_input`** scaffold.

## Concrete MS-3c payload constructor design (architecture)

This section is a **design-only** blueprint for enriching **`from_seed`**, transcript wiring, and ROM-backed fields (**`ms/comparison/`** is already **axiom-free** on Phase-1). It aligns **`ComparisonPayloadTypes.ec`**, **`ComparisonPayloadSeedTypes.ec`**, **`ComparisonPayloadFromSeed.ec`**, **`ComparisonPayloadSeedAnchors.ec`**, facade **`ComparisonPayloadSeeds.ec`**, and later **game hops** with **`ms_transcript_observable`** / **`ms_v2_transcript_observable`** (`ms/TranscriptObservable.ec`, `ms/SourceModel.ec`).

### 1. Seed carriers (replace abstract types)

**Goal:** eventually replace Phase-1 **`unit`** carriers with record or tuple types large enough to hold every **`mscp_*`** field that is **not** fixed deterministically from **`ms_public_input`** alone, and define matching **`d_ms3c_*`** laws (ROM / FS / Schnorr). Today all four seed components use **`unit`** + **`dunit`** as scaffolding only.

**Suggested split (conceptual):**

- **Challenge side (`*_seed_challenge`):** material that fixes comparison **indices**, **challenge digests** (**`mscp_global_challenge`**, **`mscp_programmed_challenge`**), and **scalar shares** (**`mscp_share_true`**, **`mscp_share_false`**) after FS / split logic—typically finite-domain draws or ROM-derived scalars/digests bounded by the MS comparison arity implied by **`x`** (needs a length discipline from **`ms_public_input`** or a separate arity field once **`ms_public_input`** is structured).

- **Announcement side (`*_seed_announcement`):** material that fixes **Schnorr announcement points** (**`mscp_ann_true`**, **`mscp_ann_false`**) and any auxiliary randomness for **simulated** false branches on the sim side; real side uses honest announcement construction, sim side uses simulator map from shares (per **`ms_false_clause_simulated`**).

**Real vs sim:** types may **coincide** structurally (same tuple shape) with different **`d_ms3c_*`** laws, or differ if sim packs extra simulator coins; the abstract API already separates real vs sim theory names.

### 2. **`ms3c_real_payload_from_seed` / `ms3c_sim_payload_from_seed`**

Define both as **total** functions **`ms_public_input` → seed → `ms3c_comparison_clause_payload`**, assembling the canonical payload record:

1. **Indices** **`mscp_true_clause_ix`**, **`mscp_false_clause_ixs`:** from challenge seed (or from **`x`** if fixed by statement); must satisfy **`0 <= true_ix`** and list length consistency so **`L_ms3c_{real,sim}_seed_index_shape_valid`** (from public-index anchors + **`ms3c_public_shape_ok`**) and **`L_ms3c_{real,sim}_constructor_false_index_nonempty`** (when **`ms3c_public_false_branch_nonempty x`**) hold for nontrivial comparisons.

2. **Shares** **`mscp_share_true`**, **`mscp_share_false`:** from challenge seed; lengths must match **`mscp_false_clause_ixs`** / **`mscp_ann_false`** arity.

3. **Announcements** **`mscp_ann_true`**, **`mscp_ann_false`:** from announcement seed (real: honest openings; sim: **`sch_pubkey`** of false shares entrywise for **`ms_false_clause_simulated`** on support).

4. **Digests** **`mscp_global_challenge`**, **`mscp_programmed_challenge`:** from challenge seed; enforce **`mscp_programmed_challenge = mscp_global_challenge`** on all seeds if the hook **`ms3c_clause_challenge_shares_sum`** is to be discharged by construction.

5. **Query digest** **`mscp_query_digest`:** set **after** announcement points are fixed, as  
   **`ms_comparison_query_digest stmt ann_digests`**  
   where **`stmt := ms3c_public_stmt_digest x`** (same as **`ms3c_comparison_stmt_digest x`** today; later align with **`ms_statement_digest`** / **`msv2_statement_digest`** via **`ms/SourceModel.ec`** and transcript bridges), and **`ann_digests`** is **`ms3c_clause_ann_digests_from_surface`** on the **folded** surface from the same payload. Phase-1 **`ms3c_phase1_payload_from_public_input`** already defines **`mscp_query_digest`** this way; **`A_ms3c_clause_surface_query_digest_constructed`** is the **proved** ROM wiring lemma; **`A_ms3c_surface_query_digest_field_correct`** lifts it given **`ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x`**.

### 3. Component distributions **`d_ms3c_*_seed_*`**

Define each as a **composition** of finitely many **`duniform`**, **`dunit`**, **`dmap`** of ROM query (lossless when the ROM read is lossless on its domain), and **independent products** where the spec samples independently. Then:

- **`A_ms3c_*_seed_*_lossless`:** all four component laws proved as lemmata (**`L_ms3c_{real,sim}_seed_challenge_lossless`**, **`L_ms3c_real_seed_announcement_lossless`**, **`L_ms3c_sim_seed_announcement_lossless`**) from **`dunit_ll`** on **`unit`**; richer carriers will use **`duniform_ll`**, **`dmap_ll`**, **`dprod_ll_auto`** as appropriate.

**Dependency:** finite **`Finite`**/`enum` carriers or proved full-support for each draw; arity of false-branch lists must be fixed from **`x`** (or carried inside **`ms_public_input`**) so **`duniform`** domains are well-typed.

### 4. Coupling vs transcript spine (risk)

The abstract coupling law is the **independent product** of real and sim **marginal** payload laws. Under Phase-1 shared **`from_seed`**, cross-marginal **field equality** for **all** public and share carriers (including **`mscp_query_digest`** *as a field* on payloads) follows from **`L_ms3c_cross_support_real_sim_payload_equal`**. ROM-consistent **surface** query digest for Phase-1 is **`A_ms3c_clause_surface_query_digest_constructed`** (**proved**). **Transcript-level design:** once real/sim **`from_seed`** diverge, reinstate fragment proof obligations as needed.

**`games/GameViews.ec`** today uses **`witness`** for **`ms_transcript_observable`** in **`mk_ms_game_view`**—constructor work must eventually pass **real** **`obs`** per stage so **`from_seed`** (or a renamed pipeline) can read comparison fields.

### 5. Axiom → discharge map (target definitions)

| Axiom group | Discharged by (intended) |
|-------------|---------------------------|
| **Seed losslessness** | All four component laws are **`dunit`** on **`unit`** with proved lemmata; no seed-component losslessness axioms remain in **`ComparisonPayloadSeedTypes.ec`**. |
| **Seed shape** | **Lemma-only** on support: index-shape (**`L_ms3c_{real,sim}_seed_index_shape_valid`**) and ann/share length (**`L_ms3c_{real,sim}_seed_length_shape_valid`**) from four proved **`A_ms3c_{real,sim}_from_seed_uses_*`** lemmas + **`ms3c_public_shape_ok`**. |
| **Public-field fragments ×4** | Phase-1: all four proved in **`ComparisonCouplingAxioms.ec`**; ROM query digest on Phase-1 payloads is **`A_ms3c_clause_surface_query_digest_constructed`** (**proved**). |
| **Challenge-share fragments ×3** | Phase-1: all three proved from **`pr = ps`**; revisit if **`from_seed`** diverges per side. |
| **False-index nonempty** | **Lemma-only:** **`L_ms3c_{real,sim}_constructor_false_index_nonempty`** from **`ms3c_public_false_branch_nonempty`**, public-index anchors, and **`ms3c_public_shape_ok`**; seed-level uses now flow through **`ms3c_false_clauses_simulator_generated`** rather than a placeholder-width lemma. |
| **False-clause simulation on support** | **`L_ms3c_false_clause_generation_on_support`** (**lemma**) from **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** (**lemmata**); Phase-1 constructor wires **`mscp_ann_false`** as **`map sch_pubkey`** of **`mscp_share_false`** (singleton **`[0]`** branch). Richer **`from_seed`** must preserve this discipline or replace with transcript-backed proof. |
| **`A_ms3c_clause_surface_query_digest_constructed`** | Phase-1: **proved**—**`mscp_query_digest`** in **`ms3c_phase1_payload_from_public_input`** is **`ms_comparison_query_digest (ms3c_public_stmt_digest x) (…)`**; richer **`from_seed`** should preserve the same **`stmt`** / ann-digest discipline so this stays **`by []`**. |

### 6. Dependency risks

| Risk | Mitigation |
|------|------------|
| **MS-3b carrier is concrete but Phase-1 seed laws are still skeletal** | Keep the native comparison slice / opening carrier stable, and replace the current **`unit`** challenge/announcement seed components with richer transcript or ROM samplers. |
| **`ms_transcript_observable`** abstract | Use **`ms/SourceModel.ec`** accessors (**`ms_statement_digest`**, **`ms_comparison_global_challenge`**, …) and **`ms_v2_transcript_observable`** refinements; add **`ms3c_observable_comparison_slice`** bridge ops or refine **`ms_public_input`** to carry statement + arity. |
| **`ms_public_input`** abstract | Need digest arity / clause count for **`duniform`** domains; may require **`ms_public_input`** refinement or side conditions on games. |
| **Game view now carries native comparison openings, but not richer sampled comparison state** | The game layer aligns phase-1 payload fields with **`ms_game_view_public_obs xms`** through native openings; future work is only about richer samplers or execution state, not about adding basic announcement/share fields. |
| **ROM / FS** | **`A_ms3c_clause_surface_query_digest_constructed`** (payload digest wiring) and proved **`A_ms3c_surface_query_digest_field_correct`**; **`ms3c_clause_challenge_shares_sum`** ties to **`hash_domain`** / ROM programming lemmas (`primitives/FS.ec`, **`ms_query_to_scalar`** path). |

### 7. Recommended implementation sequence

1. **Smallest safe patch (comments + one witness reduction only if needed):** extend the seed-bundle comment (**`ComparisonPayloadSeeds.ec`** facade) with **arity source** for false lists (pointer to future **`ms_public_input`** refinement); **no** theorem statement changes.

2. **Types (`ComparisonPayloadTypes.ec`):** replace abstract seed types with concrete tuples (or records) documented in this plan; keep **`ms3c_*_payload_seed`** as product type.

3. **Constructors (`ComparisonPayloadFromSeed.ec` / `ComparisonPayloadSeedTypes.ec`):** define **`ms3c_real_payload_from_seed`**, **`ms3c_sim_payload_from_seed`**; define **`d_ms3c_*_seed_*`**; prove **`L_ms3c_*_payload_seed_lossless`** lemmas replace axioms; prove **shape** lemmas (**`ComparisonPayloadSeedAnchors.ec`**) replace shape axioms.

4. **Digest (`ComparisonDigests.ec`):** Phase-1 **`A_ms3c_clause_surface_query_digest_constructed`** is **proved**; when **`from_seed`** is enriched, keep **`mscp_query_digest`** defined as in step (5) so the lemma stays definitional (then **`A_ms3c_surface_query_digest_field_correct`** from **`ms3c_clause_surface_to_payload`**).

5. **False clause (`ComparisonPayloadFalseClause.ec`):** constructor false-index nonemptiness is **lemma-only**; **`A_ms3c_{real,sim}_false_announcements_match_shares_on_support`** are **proved** for Phase-1 (**`sch_pubkey`** false announcements + on-support = **`ms3c_phase1_payload_from_public_input`**). When **`from_seed`** diverges from that wiring, restore transcript invariants or narrow constructor obligations accordingly.

6. **Coupling (`ComparisonCouplingAxioms.ec`):** Phase-1 **done**—all named **`A_ms3c_payload_*_match`** hooks are **lemmata** from **`L_ms3c_cross_support_real_sim_payload_equal`**. If real/sim margins stop sharing one payload image, restore fragment axioms or prove from transcript alignment.

7. **Games:** replace **`witness`** **`obs`** with constructed observable; lemmas **`L_ms_game_view_*_mk`** pattern extend to real **`obs`**.

**Expected to remain axiomatic after early patches:** properties true in the execution spec but not forced by definitions (for example ROM collision resistance or transcript-level announcement algebra once the carrier is enriched beyond Phase-1) may still stay as named axioms until constructor/transcript wiring discharges them in bulk. There are now **no** remaining MS-3b- or MS-3c-specific bridge axioms in this lane: the MS-3b operand-direction leaf and the MS-3c `game_pr` bridge are both proved lemmas.

## Next target

See **§ Concrete MS-3c payload constructor design** above: prefer **richer seed types + `from_seed` + component laws**, keeping **`stmt := ms3c_public_stmt_digest x`** for **`mscp_query_digest`** (digest constructor is **proved** for Phase-1; no `forall stmt`). The current phase has replaced raw placeholders and digest-backed comparison openings with a native comparison slice on **`ms_public_input`** and native comparison openings on **`ms_transcript_observable`**. The next concrete target is to keep that carrier/observable boundary fixed while enriching the seed samplers and execution model. **Game hop:** no additional MS-3c bridge axiom remains; **`A_MS3c_comparison_bundle_implies_game_pr_equality`** and **`A_MS3c_canonical_comparison_exact_bound`** are both proved lemmas.
