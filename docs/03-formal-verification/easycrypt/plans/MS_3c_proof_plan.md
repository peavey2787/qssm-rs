# MS-3c Proof Plan (EasyCrypt)

This note tracks **exact comparison-clause simulation** under programmed Fiat–Shamir. Definitions and the main skeleton lemma live in **`ms/Comparison.ec`**; **`ms/MS.ec`** exports the wrapper lemma **`MS_3c_exact_comparison_simulation`** (same proof as `MS_3c_exact_comparison_simulation_from_clauses` in `ms/Comparison.ec`).

## Goal (informal)

The comparison lane should be **distributionally identical** real vs sim on `ms_comparison_clause_surface`: false branches simulator-shaped, true branch consistent with **MS-3b** blinder points and Schnorr reparameterization, FS query digest from **announcement-only** material, ROM programmability (**A2**), and challenge-share / global-challenge packaging.

## Surface and payloads (`ms/Comparison.ec`)

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

## Payload-level structure (`ms/Comparison.ec`)

Support and pairing:

- **`ms3c_real_payload_on_support`** / **`ms3c_sim_payload_on_support`** — membership in **`d_ms3c_{real,sim}_comparison_payload`**.
- **`ms3c_payload_pair_public_fields_match`** — indices, announcements, query / global / programmed digests align across a real/sim payload pair on support.
- **`ms3c_payload_pair_challenge_shares_match`** — true/false share vectors align across the pair.
- **`ms3c_payload_ann_digest_list_shape_ok`** — **`ms3c_ann_digest_list_shape (ms3c_make_clause_surface p)`** (announcement-shape on the folded surface).
- **`ms3c_payload_programmed_challenge_matches_global`** — **`ms3c_clause_shares_sum_matches_global (ms3c_make_clause_surface p)`** (challenge-share consistency).

Bundled obligation predicates (inputs to the payload scheduling coupling layer):

- **`ms3c_ax_payload_public_fields_match`**, **`ms3c_ax_payload_challenge_shares_match`**, **`ms3c_ax_payload_announcements_match_shape`**, **`ms3c_ax_payload_challenge_share_consistency`**, **`ms3c_ax_payload_false_clauses_simulated`**, **`ms3c_ax_payload_true_clause_simulated`**.

## What `MS_3c_exact_comparison_simulation_from_clauses` consumes

Proof path:

1. **`A_ms3c_payload_schedule_equiv`** — **proved lemma**: five hooks ⇒ payload law equality, via the coupling/scheduling axioms (**`A_ms3c_payload_support_coupling_from_components`** + **`A_ms3c_payload_schedule_eq_from_coupling`**) and the bridge lemmas below.
2. **`A_ms3c_comparison_schedule_equiv`** — **proved lemma**: payload equality + **`qssm_dmap_congr`** (`ms/BitnessOne.ec`) with shared **`ms3c_make_clause_surface`**.
3. **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** — rewrites surface clause operators to schedules and closes **`ms_comparison_exact_simulation_equiv`**.
4. **`L_ms3c_rom_scalar_response_for_any_digest`** — unpacks **`Ha2`** (ROM / A2 surface).

**Hook → component bridges (proved):** **`L_ms3c_payload_announcements_match_shape_from_ann_hook`** (folded-surface simulatable support; uses **`L_ms3c_ann_digest_list_shape`**), **`L_ms3c_payload_challenge_share_consistency_from_sum_hook`**, **`L_ms3c_payload_true_clause_simulated_from_true_hook`**.

**`MS_3c_comparison_clause_obligations`** still packages digest / false / true / share obligations; the false branch is **payload-support** shaped (real and sim marginals), discharged from **`A_ms3c_false_clause_simulation`**. The digest branch states programmed query digest vs **`ms3c_clause_ann_digests_from_surface`** under **`A_ms3c_digest_announcement_only`** (no separate **`ms_comparison_programmed_fs_consistent`** premise in that bundle).

## Axioms vs lemmas (remaining proof debt)

| Name | Kind | Conclusion shape |
|------|------|-------------------|
| **`A_ms3c_digest_announcement_only`** | axiom | **`Hann`** + simulatable ⇒ **`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c)`** (no abstract digest list parameter; no **`ms_comparison_programmed_fs_consistent`** premise). |
| **`L_ms3c_ann_digest_list_shape`** | **lemma** | **`ms3c_ann_digest_list_shape c`** for all comparison surfaces `c`. |
| **`A_ms3c_false_clause_simulation`** | axiom | **`ms3c_false_clauses_simulator_generated`** ⇒ **`ms3c_ax_payload_false_clauses_simulated`** (false simulation on real/sim **payload support**). |
| **`L_ms3c_true_clause_schnorr_equiv_from_ms3a`** | **lemma** | Discharges **`ms3c_true_clause_schnorr_equiv`** from **`MS_3a_single_branch_schnorr_reparam`**. |
| **`A_ms3c_true_clause_from_ms3b_and_schnorr`** | **lemma** | Consumes `Htrue` components; uses **`MS_3b_true_clause_characterization`** (+ reparam-readiness witness) to derive **`ms_clause_public_point_matches_blinder`**. |
| **`A_ms3c_challenge_share_sum`** | **lemma** | Share/global alignment hook ⇒ **`ms_comparison_challenges_split`**. |
| **`A_ms3c_real_payload_support_simulatable`** / **`A_ms3c_sim_payload_support_simulatable`** | axiom | Payload support ⇒ folded surface **`ms_comparison_clause_simulatable`**. |
| **`A_ms3c_payload_public_fields_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_public_fields_match`**. |
| **`A_ms3c_payload_challenge_shares_match`** | axiom | Five hooks ⇒ **`ms3c_ax_payload_challenge_shares_match`**. |
| **`ms3c_real_sim_payload_coupled`** / **`ms3c_ax_payload_coupling_pair_relation`** / **`ms3c_ax_payload_support_coupling`** | predicate | Pairwise payload coupling, pair-relation on support, and bundled support-coupling predicate. |
| **`d_ms3c_coupling_{real,sim}_projection`** | operator | Explicit marginal projections of `d_ms3c_real_sim_payload_coupling` through `fst` / `snd`. |
| **`A_ms3c_coupling_real_marginal`** | axiom | Components ⇒ `d_ms3c_coupling_real_projection = d_ms3c_real_comparison_payload`. |
| **`A_ms3c_coupling_sim_marginal`** | axiom | Components ⇒ `d_ms3c_coupling_sim_projection = d_ms3c_sim_comparison_payload`. |
| **`A_ms3c_coupling_pair_relation`** | axiom | Components ⇒ pairwise relation on coupling support. |
| **`A_ms3c_payload_support_coupling_from_components`** | **lemma** | Packages the three narrower coupling axioms into `ms3c_ax_payload_support_coupling`. |
| **`A_ms3c_payload_schedule_eq_from_coupling`** | axiom | Coupling-layer predicate ⇒ payload distribution equality. |
| **`A_ms3c_payload_schedule_equiv`** | **lemma** | Five hooks ⇒ payload law equality (components + schedule axiom). |
| **`A_ms3c_comparison_schedule_equiv`** | **lemma** | Five hooks ⇒ **schedule** equality (`dmap` congruence from payload lemma). |
| **`ms_comparison_exact_simulation_equiv_of_schedule_eq`** | lemma | Schedule equality ⇒ **`ms_comparison_exact_simulation_equiv`**. |
| **`MS_3c_comparison_clause_obligations`** | lemma | Bundles digest / false / true / share obligations. |
| **`L_ms3c_rom_scalar_response_for_any_digest`** | lemma | **`Ha2`** ⇒ pointwise ROM responses. |

**Still open:** instantiate per-point announcement hashing (**`ms_single_bit_branch_digest`**) and **`d_ms3c_real_comparison_payload`** / **`d_ms3c_sim_comparison_payload`** from transcript / game marginals; **prove or discharge** narrowed scheduling/coupling axioms (**`A_ms3c_coupling_real_marginal`**, **`A_ms3c_coupling_sim_marginal`**, **`A_ms3c_coupling_pair_relation`**, **`A_ms3c_payload_schedule_eq_from_coupling`**), **`A_ms3c_payload_public_fields_match`**, **`A_ms3c_payload_challenge_shares_match`**, support-simulatable axioms, **`A_ms3c_false_clause_simulation`**, **`A_ms3c_digest_announcement_only`**, and the MS-3b/reparam packaging hooks (**`ms3c_true_clause_uses_ms3b_blinder_point`**, **`ms3c_true_clause_reparam_ready`**) from the game; shrink remaining MS-3c axioms toward spec-level lemmas.

## Next target

Refine payload carriers (separate real vs sim fields if the execution spec diverges), add `dmap` preimage lemmas for obligation predicates on **support** of payload laws, and/or wire the comparison marginal in **`games/Games.ec`** (G0→G1).
