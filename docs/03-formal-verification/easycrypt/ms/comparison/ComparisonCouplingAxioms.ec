require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCouplingTypes.

(* Field-level hook bridges: real vs sim payload laws are independent `dmap`
   pushforwards of seeds (`ComparisonPayloadSeeds.ec` facade). Under Phase-1, all
   public-field fragments (including query digest / `mscp_query_digest`) follow
   from shared `from_seed` + `L_ms3c_cross_support_real_sim_payload_equal`
   (`pr = ps` on cross-support). Reintroduce fragment axioms if real/sim
   `from_seed` diverge. Digest *surface* wiring vs ROM is
   `A_ms3c_clause_surface_query_digest_constructed` (proved lemma) in
   `ComparisonDigests.ec`. *)

lemma A_ms3c_payload_index_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_index_fields_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_index_fields_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_index_fields_match Heq.
qed.

lemma A_ms3c_payload_ann_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_ann_fields_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_ann_fields_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_ann_fields_match Heq.
qed.

lemma A_ms3c_payload_stmt_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_stmt_fields_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_stmt_fields_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_stmt_fields_match Heq.
qed.

lemma A_ms3c_payload_result_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_result_fields_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_result_fields_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_result_fields_match Heq.
qed.

lemma A_ms3c_payload_public_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_public_fields_match x s.
proof.
move=> x s H1 H2 H3 H4 H5.
have Hix := A_ms3c_payload_index_fields_match x s H1 H2 H3 H4 H5.
have Hann := A_ms3c_payload_ann_fields_match x s H1 H2 H3 H4 H5.
have Hstmt := A_ms3c_payload_stmt_fields_match x s H1 H2 H3 H4 H5.
have Hres := A_ms3c_payload_result_fields_match x s H1 H2 H3 H4 H5.
exact (L_ms3c_ax_payload_public_fields_match_from_fragments x s Hix Hann Hstmt Hres).
qed.

lemma A_ms3c_payload_true_challenge_share_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_true_challenge_share_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_true_challenge_share_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_true_challenge_share_match Heq.
qed.

lemma A_ms3c_payload_false_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_false_challenge_shares_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_false_challenge_shares_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_false_challenge_shares_match Heq.
qed.

lemma A_ms3c_payload_challenge_share_lengths_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_share_lengths_match x s.
proof.
move=> x s _ _ _ _ _.
rewrite /ms3c_ax_payload_challenge_share_lengths_match => pr ps Hpr Hps.
have Heq := L_ms3c_cross_support_real_sim_payload_equal x s pr ps Hpr Hps.
by rewrite /ms3c_payload_pair_challenge_share_lengths_match Heq.
qed.

lemma A_ms3c_payload_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_shares_match x s.
proof.
move=> x s H1 H2 H3 H4 H5.
have Ht := A_ms3c_payload_true_challenge_share_match x s H1 H2 H3 H4 H5.
have Hf := A_ms3c_payload_false_challenge_shares_match x s H1 H2 H3 H4 H5.
have Hl := A_ms3c_payload_challenge_share_lengths_match x s H1 H2 H3 H4 H5.
exact (L_ms3c_ax_payload_challenge_shares_match_from_fragments x s Ht Hf Hl).
qed.

(* Product coupling: fst/snd marginals match standalone laws when the opposite
   marginal is lossless (dprod_marginalL / dprod_marginalR in Distr).
   Payload-law losslessness: lemmas L_ms3c_real_comparison_payload_law_lossless and
   L_ms3c_sim_comparison_payload_law_lossless in ComparisonPayload.ec via dmap_ll from
   L_ms3c_real_payload_seed_lossless / L_ms3c_sim_payload_seed_lossless (dprod_ll_auto
   from the four component losslessness lemmata in ComparisonPayloadSeedTypes.ec).
   Predicate ms3c_ax_payload_announcements_match_shape is proved for all x,s as
   L_ms3c_ax_payload_announcements_match_shape_total (ComparisonPayload.ec), hence it
   is not a premise below. Likewise ms3c_ax_payload_announcement_digests_preserved
   follows from ms3c_ax_payload_public_fields_match via lemma
   L_ms3c_payload_announcement_digests_preserved_from_public_fields
   (ComparisonCouplingSchedule.ec), hence it is not a premise below.
   Pair-relation packaging **`A_ms3c_coupling_pair_relation`** is also a **proved
   lemma** there: independent-product support (`supp_dprod`) + the five
   `ms3c_ax_payload_*` predicates imply **`ms3c_real_sim_payload_coupled`** pointwise. *)

(* `A_ms3c_payload_schedule_eq_from_coupling` is a proved lemma in
  `ComparisonCouplingSchedule.ec`: bundled marginal correctness + pair relation on
  `d_ms3c_real_sim_payload_coupling` support force the two folded clause-surface
  maps to agree pointwise, so schedule equality follows directly at the surface
  layer rather than by collapsing payloads to a singleton support image. *)
