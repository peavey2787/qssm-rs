require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayloadSeeds.

(* On-support predicates, pair predicates, single-payload shape, schedule / constructor. *)

pred ms3c_real_payload_on_support (x : ms_public_input) (pr : ms3c_real_comparison_payload) =
  pr \in d_ms3c_real_comparison_payload x.

pred ms3c_sim_payload_on_support (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) =
  ps \in d_ms3c_sim_comparison_payload x s.

lemma L_ms3c_real_payload_on_support_eq_phase1 (x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_real_payload_on_support x pr =>
  ms3c_make_real_clause_surface pr =
    ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x).
proof.
move=> Hsup.
rewrite /ms3c_real_payload_on_support /d_ms3c_real_comparison_payload in Hsup.
case/supp_dmap: Hsup => sr [Hsr Heq].
rewrite Heq.
by apply (L_ms3c_real_payload_from_seed_on_support_eq_phase1 x sr Hsr).
qed.

lemma L_ms3c_sim_payload_on_support_eq_phase1
  (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_sim_payload_on_support x s ps =>
  ms3c_make_sim_clause_surface ps =
    ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x).
proof.
move=> Hsup.
rewrite /ms3c_sim_payload_on_support /d_ms3c_sim_comparison_payload in Hsup.
case/supp_dmap: Hsup => ss [Hss Heq].
rewrite Heq.
by apply (L_ms3c_sim_payload_from_seed_on_support_eq_phase1 x s ss Hss).
qed.

pred ms3c_payload_pair_public_fields_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_true_clause_ix = ps.`mscp_true_clause_ix /\
  pr.`mscp_false_clause_ixs = ps.`mscp_false_clause_ixs /\
  pr.`mscp_ann_true = ps.`mscp_ann_true /\
  pr.`mscp_ann_false = ps.`mscp_ann_false /\
  pr.`mscp_query_digest = ps.`mscp_query_digest /\
  pr.`mscp_global_challenge = ps.`mscp_global_challenge /\
  pr.`mscp_programmed_challenge = ps.`mscp_programmed_challenge.

pred ms3c_payload_pair_index_fields_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_true_clause_ix = ps.`mscp_true_clause_ix /\
  pr.`mscp_false_clause_ixs = ps.`mscp_false_clause_ixs.

pred ms3c_payload_pair_ann_fields_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_ann_true = ps.`mscp_ann_true /\
  pr.`mscp_ann_false = ps.`mscp_ann_false.

pred ms3c_payload_pair_stmt_fields_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_query_digest = ps.`mscp_query_digest.

pred ms3c_payload_pair_result_fields_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_global_challenge = ps.`mscp_global_challenge /\
  pr.`mscp_programmed_challenge = ps.`mscp_programmed_challenge.

pred ms3c_payload_pair_challenge_shares_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_share_true = ps.`mscp_share_true /\
  pr.`mscp_share_false = ps.`mscp_share_false.

pred ms3c_payload_pair_true_challenge_share_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_share_true = ps.`mscp_share_true.

pred ms3c_payload_pair_false_challenge_shares_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_share_false = ps.`mscp_share_false.

pred ms3c_payload_pair_challenge_share_lengths_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  size pr.`mscp_share_false = size ps.`mscp_share_false.

pred ms3c_payload_ann_digest_list_shape_ok (p : ms3c_comparison_clause_payload) =
  ms3c_ann_digest_list_shape (ms3c_make_clause_surface p).

pred ms3c_payload_programmed_challenge_matches_global (p : ms3c_comparison_clause_payload) =
  ms3c_clause_shares_sum_matches_global (ms3c_make_clause_surface p).

pred ms3c_payload_length_index_shapes_ok (p : ms3c_comparison_clause_payload) =
  0 <= p.`mscp_true_clause_ix /\
  size p.`mscp_ann_false = size p.`mscp_share_false /\
  size p.`mscp_ann_false = size p.`mscp_false_clause_ixs.

lemma L_ms3c_real_payload_ann_digest_list_shape_ok (_x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_payload_ann_digest_list_shape_ok pr.
proof.
rewrite /ms3c_payload_ann_digest_list_shape_ok.
exact (L_ms3c_ann_digest_list_shape (ms3c_make_real_clause_surface pr)).
qed.

lemma L_ms3c_sim_payload_ann_digest_list_shape_ok (_x : ms_public_input) (_s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_payload_ann_digest_list_shape_ok ps.
proof.
rewrite /ms3c_payload_ann_digest_list_shape_ok.
exact (L_ms3c_ann_digest_list_shape (ms3c_make_sim_clause_surface ps)).
qed.

lemma L_ms3c_real_payload_on_support_ann_shape (x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_real_payload_on_support x pr =>
  ms3c_payload_ann_digest_list_shape_ok pr.
proof.
by move=> _; apply (L_ms3c_real_payload_ann_digest_list_shape_ok x pr).
qed.

lemma L_ms3c_sim_payload_on_support_ann_shape (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_sim_payload_on_support x s ps =>
  ms3c_payload_ann_digest_list_shape_ok ps.
proof.
by move=> _; apply (L_ms3c_sim_payload_ann_digest_list_shape_ok x s ps).
qed.

pred ms3c_false_clauses_payload_schedule_nontrivial (x : ms_public_input) (s : seed) =
  (exists (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr /\ 0 < size pr.`mscp_ann_false) \/
  (exists (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps /\ 0 < size ps.`mscp_ann_false).

lemma A_ms3c_real_payload_support_length_index_shapes :
  forall (x : ms_public_input) (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_payload_length_index_shapes_ok pr.
proof.
move=> x pr Hsup.
have Hseed : exists (sr : ms3c_real_payload_seed),
  sr \in d_ms3c_real_payload_seed x /\ pr = ms3c_real_payload_from_seed x sr.
  rewrite /ms3c_real_payload_on_support /d_ms3c_real_comparison_payload in Hsup.
  case/supp_dmap: Hsup => sr [Hsr Heq].
  exists sr.
  by split.
case: Hseed => sr [Hsr Hpr].
rewrite Hpr /ms3c_payload_length_index_shapes_ok.
have Hshare : ms3c_real_from_seed_share_length_anchor x sr
  by exact (A_ms3c_real_from_seed_uses_share_length x sr Hsr).
have Hlen := L_ms3c_real_seed_length_shape_valid x sr Hshare.
have Hanchor : ms3c_real_from_seed_public_index_anchor x sr
  by exact (A_ms3c_real_from_seed_uses_public_indices x sr Hsr).
have [Hix Hidx] := L_ms3c_real_seed_index_shape_valid x sr Hsr.
by split; [exact Hix | split; [exact Hlen | exact Hidx] ].
qed.

lemma A_ms3c_sim_payload_support_length_index_shapes :
  forall (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_length_index_shapes_ok ps.
proof.
move=> x s ps Hsup.
have Hseed : exists (ss : ms3c_sim_payload_seed),
  ss \in d_ms3c_sim_payload_seed x s /\ ps = ms3c_sim_payload_from_seed x s ss.
  rewrite /ms3c_sim_payload_on_support /d_ms3c_sim_comparison_payload in Hsup.
  case/supp_dmap: Hsup => ss [Hss Heq].
  exists ss.
  by split.
case: Hseed => ss [Hss Hps].
rewrite Hps /ms3c_payload_length_index_shapes_ok.
have Hshare : ms3c_sim_from_seed_share_length_anchor x s ss
  by exact (A_ms3c_sim_from_seed_uses_share_length x s ss Hss).
have Hlen := L_ms3c_sim_seed_length_shape_valid x s ss Hshare.
have Hanchor : ms3c_sim_from_seed_public_index_anchor x s ss
  by exact (A_ms3c_sim_from_seed_uses_public_indices x s ss Hss).
have [Hix Hidx] := L_ms3c_sim_seed_index_shape_valid x s ss Hss.
by split; [exact Hix | split; [exact Hlen | exact Hidx] ].
qed.

pred ms3c_real_clause_surface_in_constructor_image (c : ms_comparison_clause_surface) =
  exists (p : ms3c_real_comparison_payload), c = ms3c_make_real_clause_surface p.

pred ms3c_sim_clause_surface_in_constructor_image (c : ms_comparison_clause_surface) =
  exists (p : ms3c_sim_comparison_payload), c = ms3c_make_sim_clause_surface p.

lemma ms3c_real_comparison_schedule_in_constructor_image
  (x : ms_public_input) (c : ms_comparison_clause_surface) :
  c \in d_ms3c_real_comparison_schedule x =>
  ms3c_real_clause_surface_in_constructor_image c.
proof.
move=> Hmem.
rewrite /d_ms3c_real_comparison_schedule in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
exists p.
by rewrite Heq /ms3c_make_real_clause_surface.
qed.

lemma ms3c_sim_comparison_schedule_in_constructor_image
  (x : ms_public_input) (s : seed) (c : ms_comparison_clause_surface) :
  c \in d_ms3c_sim_comparison_schedule x s =>
  ms3c_sim_clause_surface_in_constructor_image c.
proof.
move=> Hmem.
rewrite /d_ms3c_sim_comparison_schedule in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
exists p.
by rewrite Heq /ms3c_make_sim_clause_surface.
qed.

lemma ms_comparison_exact_simulation_equiv_of_schedule_eq (x : ms_public_input) (s : seed) :
  d_ms3c_real_comparison_schedule x = d_ms3c_sim_comparison_schedule x s =>
  ms_comparison_exact_simulation_equiv x s.
proof.
move=> Heq.
by rewrite /ms_comparison_exact_simulation_equiv /d_ms3c_comparison_real_clause
  /d_ms3c_comparison_sim_clause Heq.
qed.
