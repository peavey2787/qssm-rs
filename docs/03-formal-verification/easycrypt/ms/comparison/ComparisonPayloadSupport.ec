require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayloadSeeds.

(* On-support predicates, obligation-sized payload predicates, and shape lemmas. *)

pred ms3c_real_payload_on_support (x : ms_public_input) (pr : ms3c_real_comparison_payload) =
  pr \in d_ms3c_real_comparison_payload x.

pred ms3c_sim_payload_on_support (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) =
  ps \in d_ms3c_sim_comparison_payload x s.

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

pred ms3c_ax_payload_public_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_public_fields_match pr ps.

pred ms3c_ax_payload_index_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_index_fields_match pr ps.

pred ms3c_ax_payload_ann_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_ann_fields_match pr ps.

pred ms3c_ax_payload_stmt_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_stmt_fields_match pr ps.

pred ms3c_ax_payload_result_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_result_fields_match pr ps.

lemma L_ms3c_ax_payload_public_fields_match_from_fragments
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_index_fields_match x s =>
  ms3c_ax_payload_ann_fields_match x s =>
  ms3c_ax_payload_stmt_fields_match x s =>
  ms3c_ax_payload_result_fields_match x s =>
  ms3c_ax_payload_public_fields_match x s.
proof.
move=> Hix Hann Hstmt Hres.
rewrite /ms3c_ax_payload_public_fields_match => pr ps Hpr Hps.
move: (Hix pr ps Hpr Hps) (Hann pr ps Hpr Hps) (Hstmt pr ps Hpr Hps) (Hres pr ps Hpr Hps).
move=> [Hi1 Hi2] [Ha1 Ha2] Hq [Hg Hp].
rewrite /ms3c_payload_pair_public_fields_match.
split; first exact Hi1.
split; first exact Hi2.
split; first exact Ha1.
split; first exact Ha2.
split; first exact Hq.
split; first exact Hg.
exact Hp.
qed.

pred ms3c_ax_payload_challenge_shares_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_challenge_shares_match pr ps.

pred ms3c_ax_payload_true_challenge_share_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_true_challenge_share_match pr ps.

pred ms3c_ax_payload_false_challenge_shares_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_false_challenge_shares_match pr ps.

pred ms3c_ax_payload_challenge_share_lengths_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_challenge_share_lengths_match pr ps.

(* `ms3c_ax_payload_challenge_share_lengths_match` is not used in the proof body
   below: list equality from the false-branch fragment implies matching lengths.
   The separate length obligation is for incremental game discharges (e.g. shape
   before pointwise list agreement). *)
lemma L_ms3c_ax_payload_challenge_shares_match_from_fragments
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_true_challenge_share_match x s =>
  ms3c_ax_payload_false_challenge_shares_match x s =>
  ms3c_ax_payload_challenge_share_lengths_match x s =>
  ms3c_ax_payload_challenge_shares_match x s.
proof.
move=> Ht Hf _Hlen pr ps Hpr Hps.
have Ht' := Ht pr ps Hpr Hps.
have Hf' := Hf pr ps Hpr Hps.
rewrite /ms3c_payload_pair_challenge_shares_match.
by split.
qed.

pred ms3c_ax_payload_announcement_digests_preserved (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_clause_ann_digests_from_surface (ms3c_make_real_clause_surface pr) =
    ms3c_clause_ann_digests_from_surface (ms3c_make_sim_clause_surface ps).

pred ms3c_ax_payload_announcements_match_shape (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_payload_ann_digest_list_shape_ok pr) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_ann_digest_list_shape_ok ps).

lemma L_ms3c_ax_payload_announcements_match_shape_total
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_announcements_match_shape x s.
proof.
rewrite /ms3c_ax_payload_announcements_match_shape.
split.
  move=> pr _.
  exact (L_ms3c_real_payload_ann_digest_list_shape_ok x pr).
move=> ps _.
exact (L_ms3c_sim_payload_ann_digest_list_shape_ok x s ps).
qed.

pred ms3c_ax_payload_challenge_share_consistency (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_payload_programmed_challenge_matches_global pr) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_programmed_challenge_matches_global ps).

pred ms3c_ax_payload_false_clauses_simulated (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_false_clause_simulated (ms3c_make_real_clause_surface pr)) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_false_clause_simulated (ms3c_make_sim_clause_surface ps)).

pred ms3c_ax_payload_true_clause_simulated (x : ms_public_input) (s : seed) =
  (forall (vb tb : bool list) (p : int) (r : scalar) (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_true_clause_simulates_from_blinder_points vb tb p r (ms3c_make_real_clause_surface pr) =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder
      (ms3c_make_real_clause_surface pr).`mscc_ann_true true r) /\
  (forall (vb tb : bool list) (p : int) (r : scalar) (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_true_clause_simulates_from_blinder_points vb tb p r (ms3c_make_sim_clause_surface ps) =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder
      (ms3c_make_sim_clause_surface ps).`mscc_ann_true true r).

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
have Hlen := A_ms3c_real_seed_length_shape_valid x sr.
have [Hix Hidx] := A_ms3c_real_seed_index_shape_valid x sr.
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
have Hlen := A_ms3c_sim_seed_length_shape_valid x s ss.
have [Hix Hidx] := A_ms3c_sim_seed_index_shape_valid x s ss.
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
