require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCouplingTypes.

(* Field-level hook bridges: real vs sim payload laws are independent `dmap`
   pushforwards of seeds (`ComparisonPayloadSeeds.ec` facade). The hook proofs
   below no longer rely on cross-support payload equality: they unpack each side's
   support witness and use the existing field-by-field `from_seed` equalities for
   the compared public/share surface only. This keeps sampled coins free to become
   payload-visible without forcing full real/sim payload collapse. Digest *surface*
   wiring vs ROM is
   `A_ms3c_clause_surface_query_digest_constructed` (proved lemma) in
   `ComparisonDigests.ec`. *)

lemma L_ms3c_real_payload_on_support_phase1_fields
  (x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_real_payload_on_support x pr =>
  pr.`mscp_true_clause_ix =
    (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix /\
  pr.`mscp_false_clause_ixs =
    (ms3c_phase1_payload_from_public_input x).`mscp_false_clause_ixs /\
  pr.`mscp_ann_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_true /\
  pr.`mscp_ann_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_false /\
  pr.`mscp_share_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_true /\
  pr.`mscp_share_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_false /\
  pr.`mscp_global_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge /\
  pr.`mscp_query_digest =
    (ms3c_phase1_payload_from_public_input x).`mscp_query_digest /\
  pr.`mscp_programmed_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge.
proof.
move=> Hpr.
rewrite /ms3c_real_payload_on_support /d_ms3c_real_comparison_payload in Hpr.
case/supp_dmap: Hpr => sr [Hsr Hpr].
rewrite Hpr.
exact (L_ms3c_real_payload_from_seed_support_phase1_fields x sr Hsr).
qed.

lemma L_ms3c_sim_payload_on_support_phase1_fields
  (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_sim_payload_on_support x s ps =>
  ps.`mscp_true_clause_ix =
    (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix /\
  ps.`mscp_false_clause_ixs =
    (ms3c_phase1_payload_from_public_input x).`mscp_false_clause_ixs /\
  ps.`mscp_ann_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_true /\
  ps.`mscp_ann_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_false /\
  ps.`mscp_share_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_true /\
  ps.`mscp_share_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_false /\
  ps.`mscp_global_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge /\
  ps.`mscp_query_digest =
    (ms3c_phase1_payload_from_public_input x).`mscp_query_digest /\
  ps.`mscp_programmed_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge.
proof.
move=> Hps.
rewrite /ms3c_sim_payload_on_support /d_ms3c_sim_comparison_payload in Hps.
case/supp_dmap: Hps => ss [Hss Hps].
rewrite Hps.
exact (L_ms3c_sim_payload_from_seed_support_phase1_fields x s ss Hss).
qed.

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
have [Hr_true [Hr_false _]] := L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [Hs_true [Hs_false _]] := L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
rewrite /ms3c_payload_pair_index_fields_match.
split.
  by rewrite Hr_true Hs_true.
by rewrite Hr_false Hs_false.
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
have [_ [_ [Hr_ann_true [Hr_ann_false _]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [Hs_ann_true [Hs_ann_false _]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
rewrite /ms3c_payload_pair_ann_fields_match.
split.
  by rewrite Hr_ann_true Hs_ann_true.
by rewrite Hr_ann_false Hs_ann_false.
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
have [_ [_ [_ [_ [_ [_ [_ [Hr_query _]]]]]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [_ [_ [_ [_ [_ [Hs_query _]]]]]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
by rewrite /ms3c_payload_pair_stmt_fields_match Hr_query Hs_query.
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
have [_ [_ [_ [_ [_ [_ [Hr_global [_ Hr_prog]]]]]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [_ [_ [_ [_ [Hs_global [_ Hs_prog]]]]]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
rewrite /ms3c_payload_pair_result_fields_match.
split.
  by rewrite Hr_global Hs_global.
by rewrite Hr_prog Hs_prog.
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
have [_ [_ [_ [_ [Hr_share_true _]]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [_ [_ [Hs_share_true _]]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
by rewrite /ms3c_payload_pair_true_challenge_share_match Hr_share_true Hs_share_true.
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
have [_ [_ [_ [_ [_ [Hr_share_false _]]]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [_ [_ [_ [Hs_share_false _]]]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
by rewrite /ms3c_payload_pair_false_challenge_shares_match Hr_share_false Hs_share_false.
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
have [_ [_ [_ [_ [_ [Hr_share_false _]]]]]] :=
  L_ms3c_real_payload_on_support_phase1_fields x pr Hpr.
have [_ [_ [_ [_ [_ [Hs_share_false _]]]]]] :=
  L_ms3c_sim_payload_on_support_phase1_fields x s ps Hps.
by rewrite /ms3c_payload_pair_challenge_share_lengths_match Hr_share_false Hs_share_false.
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
