require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* ------------------------------------------------------------------------- *)
(* Payload laws as pushforwards of seed samplers. Each side splits into     *)
(* abstract challenge material (indices, digests, shares, …) and abstract   *)
(* announcement draws; the joint seed law is an independent product.        *)
(* Combined seed losslessness is proved (`L_ms3c_*_payload_seed_lossless`)   *)
(* from four narrow axioms via `dprod_ll_auto` (Distr).                       *)
(* Losslessness of payload laws follows from `dmap_ll` (Distr).               *)
(* ------------------------------------------------------------------------- *)

type ms3c_real_seed_challenge.
type ms3c_real_seed_announcement.
type ms3c_sim_seed_challenge.
type ms3c_sim_seed_announcement.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).

op d_ms3c_real_seed_challenge (x : ms_public_input) : ms3c_real_seed_challenge distr.
op d_ms3c_real_seed_announcement (x : ms_public_input) : ms3c_real_seed_announcement distr.

op d_ms3c_sim_seed_challenge (x : ms_public_input) (s : seed) : ms3c_sim_seed_challenge distr.
op d_ms3c_sim_seed_announcement (x : ms_public_input) (s : seed) : ms3c_sim_seed_announcement distr.

op d_ms3c_real_payload_seed (x : ms_public_input) : ms3c_real_payload_seed distr =
  d_ms3c_real_seed_challenge x `*` d_ms3c_real_seed_announcement x.

op d_ms3c_sim_payload_seed (x : ms_public_input) (s : seed) : ms3c_sim_payload_seed distr =
  d_ms3c_sim_seed_challenge x s `*` d_ms3c_sim_seed_announcement x s.

axiom A_ms3c_real_seed_challenge_lossless :
  forall (x : ms_public_input), is_lossless (d_ms3c_real_seed_challenge x).

axiom A_ms3c_real_seed_announcement_lossless :
  forall (x : ms_public_input), is_lossless (d_ms3c_real_seed_announcement x).

axiom A_ms3c_sim_seed_challenge_lossless :
  forall (x : ms_public_input) (s : seed), is_lossless (d_ms3c_sim_seed_challenge x s).

axiom A_ms3c_sim_seed_announcement_lossless :
  forall (x : ms_public_input) (s : seed), is_lossless (d_ms3c_sim_seed_announcement x s).

lemma L_ms3c_real_payload_seed_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_payload_seed x).
proof.
by rewrite /d_ms3c_real_payload_seed; apply dprod_ll_auto;
  [apply (A_ms3c_real_seed_challenge_lossless x) |
   apply (A_ms3c_real_seed_announcement_lossless x)].
qed.

lemma L_ms3c_sim_payload_seed_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_payload_seed x s).
proof.
by rewrite /d_ms3c_sim_payload_seed; apply dprod_ll_auto;
  [apply (A_ms3c_sim_seed_challenge_lossless x s) |
   apply (A_ms3c_sim_seed_announcement_lossless x s)].
qed.

op ms3c_real_payload_from_seed (x : ms_public_input) :
  ms3c_real_payload_seed -> ms3c_real_comparison_payload.

op ms3c_sim_payload_from_seed (x : ms_public_input) (s : seed) :
  ms3c_sim_payload_seed -> ms3c_sim_comparison_payload.

(* Narrow seed-shape obligations: payloads emitted by constructors from seed
   material satisfy the length/index shape discipline. *)
axiom A_ms3c_real_seed_length_shape_valid :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    size (ms3c_real_payload_from_seed x sr).`mscp_share_false.

axiom A_ms3c_real_seed_index_shape_valid :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 <= (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix /\
    size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.

axiom A_ms3c_sim_seed_length_shape_valid :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    size (ms3c_sim_payload_from_seed x s ss).`mscp_share_false.

axiom A_ms3c_sim_seed_index_shape_valid :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 <= (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix /\
    size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.

op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_payload_seed x) (ms3c_real_payload_from_seed x).

op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_payload_seed x s) (ms3c_sim_payload_from_seed x s).

lemma L_ms3c_real_comparison_payload_law_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_comparison_payload x).
proof.
by rewrite /d_ms3c_real_comparison_payload; apply dmap_ll;
  apply (L_ms3c_real_payload_seed_lossless x).
qed.

lemma L_ms3c_sim_comparison_payload_law_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_comparison_payload x s).
proof.
by rewrite /d_ms3c_sim_comparison_payload; apply dmap_ll;
  apply (L_ms3c_sim_payload_seed_lossless x s).
qed.

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

(* Length / index / arity well-formedness on the raw payload (definitionally matches
   `ms_comparison_clause_simulatable (ms3c_make_clause_surface p)`). *)
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

(* Support-local “false branch has positive width” (payload laws), vs the global
   existential in `ms3c_false_clauses_simulator_generated`. *)
pred ms3c_false_clauses_payload_schedule_nontrivial (x : ms_public_input) (s : seed) =
  (exists (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr /\ 0 < size pr.`mscp_ann_false) \/
  (exists (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps /\ 0 < size ps.`mscp_ann_false).

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

(* Scheduling: payload laws realize length/index/arity shapes on support (narrower than
   full `ms_comparison_clause_simulatable`; packaging is proved in
   `L_ms3c_{real,sim}_payload_support_simulatable`). *)
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

(* Bridge: game-layer “some simulatable surface with false width” ⇒ payload-schedule
   carries some on-support payload with positive false-announcement width. *)
axiom A_ms3c_real_constructor_false_index_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.

axiom A_ms3c_sim_constructor_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.

lemma A_ms3c_real_seed_false_index_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
by move=> x sr; exact (A_ms3c_real_constructor_false_index_nonempty x sr).
qed.

lemma A_ms3c_sim_seed_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
by move=> x s ss; exact (A_ms3c_sim_constructor_false_index_nonempty x s ss).
qed.

lemma A_ms3c_real_seed_false_clause_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_ann_false.
proof.
move=> x sr.
have Hix_pos := A_ms3c_real_seed_false_index_nonempty x sr.
have [_ Hshape] := A_ms3c_real_seed_index_shape_valid x sr.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_sim_seed_false_clause_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false.
proof.
move=> x s ss.
have Hix_pos := A_ms3c_sim_seed_false_index_nonempty x s ss.
have [_ Hshape] := A_ms3c_sim_seed_index_shape_valid x s ss.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_false_clauses_hook_implies_schedule_nontrivial :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_false_clauses_payload_schedule_nontrivial x s.
proof.
move=> x s _.
have Hll : is_lossless (d_ms3c_real_payload_seed x).
  exact (L_ms3c_real_payload_seed_lossless x).
have Hmu : mu (d_ms3c_real_payload_seed x) predT <> 0%r.
  rewrite /is_lossless /weight in Hll.
  by rewrite Hll.
have [sr Hsr] : exists (sr : ms3c_real_payload_seed), sr \in d_ms3c_real_payload_seed x.
  have [sr [Hsr _]] := neq0_mu (d_ms3c_real_payload_seed x) predT Hmu.
  by exists sr.
left.
exists (ms3c_real_payload_from_seed x sr).
split.
  rewrite /ms3c_real_payload_on_support /d_ms3c_real_comparison_payload.
  apply supp_dmap.
  by exists sr.
exact (A_ms3c_real_seed_false_clause_nonempty x sr).
qed.

(* False-clause simulation on real/sim **payload support** only; premise is the
   support-local nontriviality predicate (not the global existential hook). *)
axiom A_ms3c_false_clause_generation_on_support :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_false_clauses_simulated x s.

lemma A_ms3c_false_clause_simulation :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_payload_schedule_nontrivial x s =>
    ms3c_ax_payload_false_clauses_simulated x s.
proof.
by move=> x s _; exact (A_ms3c_false_clause_generation_on_support x s).
qed.

lemma L_ms_comparison_clause_simulatable_of_payload_length_index
  (p : ms3c_comparison_clause_payload) :
  ms3c_payload_length_index_shapes_ok p =>
  ms_comparison_clause_simulatable (ms3c_make_clause_surface p).
proof.
move=> H.
rewrite /ms_comparison_clause_simulatable /ms3c_make_clause_surface /=.
by [].
qed.

lemma L_ms3c_real_payload_support_simulatable (x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_real_payload_on_support x pr =>
  ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr).
proof.
move=> Hsup.
apply (L_ms_comparison_clause_simulatable_of_payload_length_index pr).
exact (A_ms3c_real_payload_support_length_index_shapes x pr Hsup).
qed.

lemma L_ms3c_sim_payload_support_simulatable (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_sim_payload_on_support x s ps =>
  ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).
proof.
move=> Hsup.
apply (L_ms_comparison_clause_simulatable_of_payload_length_index ps).
exact (A_ms3c_sim_payload_support_length_index_shapes x s ps Hsup).
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
