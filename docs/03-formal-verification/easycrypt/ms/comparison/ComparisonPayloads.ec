require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* Abstract payload laws (scheduling from `ms_public_input` / `seed`). *)
op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr.
op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr.

op d_ms3c_real_comparison_schedule (x : ms_public_input) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_real_comparison_payload x) ms3c_make_real_clause_surface.

op d_ms3c_sim_comparison_schedule (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_sim_comparison_payload x s) ms3c_make_sim_clause_surface.

(* Surface clause distributions = schedules. *)
op d_ms3c_comparison_real_clause (x : ms_public_input) : ms_comparison_clause_surface distr =
  d_ms3c_real_comparison_schedule x.

op d_ms3c_comparison_sim_clause (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  d_ms3c_sim_comparison_schedule x s.

pred ms_comparison_exact_simulation_equiv (x : ms_public_input) (s : seed) =
  d_ms3c_comparison_real_clause x = d_ms3c_comparison_sim_clause x s.

(* ------------------------------------------------------------------------- *)
(* Payload-level support and real/sim comparison predicates.               *)
(* ------------------------------------------------------------------------- *)

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

pred ms3c_payload_pair_challenge_shares_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  pr.`mscp_share_true = ps.`mscp_share_true /\
  pr.`mscp_share_false = ps.`mscp_share_false.

pred ms3c_payload_ann_digest_list_shape_ok (p : ms3c_comparison_clause_payload) =
  ms3c_ann_digest_list_shape (ms3c_make_clause_surface p).

pred ms3c_payload_programmed_challenge_matches_global (p : ms3c_comparison_clause_payload) =
  ms3c_clause_shares_sum_matches_global (ms3c_make_clause_surface p).

(* Obligation-sized payload predicates (used by schedule-from-components). *)

pred ms3c_ax_payload_public_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_public_fields_match pr ps.

pred ms3c_ax_payload_challenge_shares_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_challenge_shares_match pr ps.

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

(* Scheduling: payload laws only realize simulatable folded surfaces. *)
axiom A_ms3c_real_payload_support_simulatable :
  forall (x : ms_public_input) (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr).

axiom A_ms3c_sim_payload_support_simulatable :
  forall (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).

(* Tightened vs forall-simulatable: only payloads on real/sim comparison support. *)
axiom A_ms3c_false_clause_simulation :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_ax_payload_false_clauses_simulated x s.

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
