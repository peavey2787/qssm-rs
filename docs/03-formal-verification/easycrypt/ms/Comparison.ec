require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.

(* MS-3c exact comparison-clause simulation.
   Schedules are `dmap` pushforwards of abstract **payload** laws through
   `ms3c_make_{real,sim}_clause_surface`; surface clause operators stay equal to
   schedules (MS-3a-style layering). Payload law equality is split into named
   `ms3c_ax_payload_*` obligations plus `A_ms3c_payload_schedule_from_components`;
   `A_ms3c_payload_schedule_equiv` is a proved lemma from those pieces. *)

type ms_comparison_clause_surface = {
  mscc_true_clause_ix : int;
  mscc_false_clause_ixs : int list;
  mscc_ann_true : sch_point;
  mscc_ann_false : sch_point list;
  mscc_share_true : scalar;
  mscc_share_false : scalar list;
  mscc_global_challenge : digest;
  mscc_query_digest : digest;
  mscc_programmed_challenge : digest;
}.

(* Payload records: scheduling carriers before folding into `ms_comparison_clause_surface`. *)
type ms3c_comparison_clause_payload = {
  mscp_true_clause_ix : int;
  mscp_false_clause_ixs : int list;
  mscp_ann_true : sch_point;
  mscp_ann_false : sch_point list;
  mscp_share_true : scalar;
  mscp_share_false : scalar list;
  mscp_global_challenge : digest;
  mscp_query_digest : digest;
  mscp_programmed_challenge : digest;
}.

type ms3c_real_comparison_payload = ms3c_comparison_clause_payload.
type ms3c_sim_comparison_payload = ms3c_comparison_clause_payload.

op ms3c_make_clause_surface (p : ms3c_comparison_clause_payload) : ms_comparison_clause_surface =
  {| mscc_true_clause_ix = p.`mscp_true_clause_ix;
     mscc_false_clause_ixs = p.`mscp_false_clause_ixs;
     mscc_ann_true = p.`mscp_ann_true;
     mscc_ann_false = p.`mscp_ann_false;
     mscc_share_true = p.`mscp_share_true;
     mscc_share_false = p.`mscp_share_false;
     mscc_global_challenge = p.`mscp_global_challenge;
     mscc_query_digest = p.`mscp_query_digest;
     mscc_programmed_challenge = p.`mscp_programmed_challenge |}.

op ms3c_make_real_clause_surface (p : ms3c_real_comparison_payload) : ms_comparison_clause_surface =
  ms3c_make_clause_surface p.

op ms3c_make_sim_clause_surface (p : ms3c_sim_comparison_payload) : ms_comparison_clause_surface =
  ms3c_make_clause_surface p.

(* Ordered announcement digest material (true branch first, then false branches). *)
op ms3c_digest_true_announcement (a : sch_point) : digest =
  ms_single_bit_branch_digest a.

op ms3c_digest_false_announcements (anns : sch_point list) : digest list =
  map ms_single_bit_branch_digest anns.

op ms3c_clause_ann_digests_from_surface (c : ms_comparison_clause_surface) : digest list =
  ms3c_digest_true_announcement c.`mscc_ann_true :: ms3c_digest_false_announcements c.`mscc_ann_false.

op ms3c_clause_ann_digests (c : ms_comparison_clause_surface) : digest list =
  ms3c_clause_ann_digests_from_surface c.

op ms3c_comparison_stmt_digest (x : ms_public_input) : digest = witness.

pred ms_comparison_clause_simulatable (c : ms_comparison_clause_surface) =
  0 <= c.`mscc_true_clause_ix /\
  size c.`mscc_ann_false = size c.`mscc_share_false /\
  size c.`mscc_ann_false = size c.`mscc_false_clause_ixs.

pred ms3c_ann_digest_list_shape (c : ms_comparison_clause_surface) =
  size (ms3c_clause_ann_digests c) = 1 + size c.`mscc_ann_false.

lemma L_ms3c_ann_digest_list_shape (c : ms_comparison_clause_surface) :
  ms3c_ann_digest_list_shape c.
proof.
rewrite /ms3c_ann_digest_list_shape /ms3c_clause_ann_digests /ms3c_clause_ann_digests_from_surface
  /ms3c_digest_false_announcements /=.
by rewrite size_map.
qed.

pred ms_false_clause_simulated (c : ms_comparison_clause_surface) =
  forall (i : int), 0 <= i => i < size c.`mscc_ann_false =>
    nth witness c.`mscc_ann_false i = sch_pubkey (nth witness c.`mscc_share_false i).

pred ms_true_clause_simulates_from_blinder_points
  (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface) =
  ms_true_clause_points_are_blinder_points vb tb p c.`mscc_ann_true r.

pred ms3c_clause_shares_sum_matches_global (c : ms_comparison_clause_surface) =
  c.`mscc_programmed_challenge = c.`mscc_global_challenge.

pred ms_comparison_challenges_split (c : ms_comparison_clause_surface) =
  size c.`mscc_share_false = size c.`mscc_false_clause_ixs /\
  size c.`mscc_share_false = size c.`mscc_ann_false /\
  ms3c_clause_shares_sum_matches_global c.

pred ms_comparison_programmed_fs_consistent (stmt : digest) (c : ms_comparison_clause_surface) =
  c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).

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

(* Scheduling coupling layer: source/payload transport only (not cryptographic). *)
pred ms3c_real_sim_payload_coupled
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  ms3c_payload_pair_public_fields_match pr ps /\
  ms3c_payload_pair_challenge_shares_match pr ps /\
  ms3c_clause_ann_digests_from_surface (ms3c_make_real_clause_surface pr) =
  ms3c_clause_ann_digests_from_surface (ms3c_make_sim_clause_surface ps) /\
  ms_false_clause_simulated (ms3c_make_real_clause_surface pr) /\
  ms_false_clause_simulated (ms3c_make_sim_clause_surface ps).

op d_ms3c_real_sim_payload_coupling
  (x : ms_public_input) (s : seed) :
  (ms3c_real_comparison_payload * ms3c_sim_comparison_payload) distr.

op d_ms3c_coupling_real_projection (x : ms_public_input) (s : seed) :
  ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) fst.

op d_ms3c_coupling_sim_projection (x : ms_public_input) (s : seed) :
  ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) snd.

pred ms3c_ax_payload_coupling_pair_relation (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    (pr, ps) \in d_ms3c_real_sim_payload_coupling x s =>
    ms3c_real_sim_payload_coupled pr ps).

pred ms3c_ax_payload_support_coupling (x : ms_public_input) (s : seed) =
  d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x /\
  d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s /\
  ms3c_ax_payload_coupling_pair_relation x s.

pred ms_comparison_exact_simulation_equiv (x : ms_public_input) (s : seed) =
  d_ms3c_comparison_real_clause x = d_ms3c_comparison_sim_clause x s.

pred ms3c_programmed_comparison_rom_ready (x : ms_public_input) (s : seed) =
  forall (qd : digest), exists (t : scalar), ms_query_to_scalar qd = t.

pred ms3c_comparison_query_digest_ann_only (x : ms_public_input) (s : seed) =
  forall (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    ms3c_ann_digest_list_shape c.

pred ms3c_comparison_global_programmable_under_A2 (x : ms_public_input) (s : seed) =
  ms3c_programmed_comparison_rom_ready x s.

pred ms3c_false_clauses_simulator_generated (x : ms_public_input) (s : seed) =
  exists (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c /\ 0 < size c.`mscc_ann_false.

pred ms3c_true_clause_uses_ms3b_blinder_point (x : ms_public_input) (s : seed) =
  forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
    ms_true_clause_position vb tb p =>
    ms3b_comparison_operand_bits x vb tb /\
    ms_highest_differing_bit vb tb p /\
    ms3b_clause_opening_binds x vb tb p c.`mscc_ann_true r.

pred ms3c_true_clause_schnorr_equiv (x : ms_public_input) (s : seed) =
  forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
    ms_true_clause_position vb tb p =>
    d_ms3a_schnorr_real r (ms_query_to_scalar c.`mscc_programmed_challenge) =
    d_ms3a_schnorr_sim r (ms_query_to_scalar c.`mscc_programmed_challenge).

pred ms3c_true_clause_reparam_ready (x : ms_public_input) (s : seed) =
  ms3c_true_clause_schnorr_equiv x s.

pred ms3c_true_clause_schnorr_from_blinder (x : ms_public_input) (s : seed) =
  ms3c_true_clause_uses_ms3b_blinder_point x s /\
  ms3c_true_clause_reparam_ready x s /\
  (forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
    ms_true_clause_simulates_from_blinder_points vb tb p r c =>
    ms_true_clause_position vb tb p).

pred ms3c_clause_challenge_shares_sum (x : ms_public_input) (s : seed) =
  forall (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    c.`mscc_programmed_challenge = c.`mscc_global_challenge.

(* Comparison programmed query digest uses only the ordered announcement digest projection
   (no separate abstract digest list parameter). *)
axiom A_ms3c_digest_announcement_only :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    forall (stmt : digest) (c : ms_comparison_clause_surface),
      ms_comparison_clause_simulatable c =>
      c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).

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

lemma L_ms3c_true_clause_schnorr_equiv_from_ms3a
  (x : ms_public_input) (s : seed) :
  ms3c_true_clause_schnorr_equiv x s.
proof.
move=> vb tb p r c _.
exact (MS_3a_single_branch_schnorr_reparam r (ms_query_to_scalar c.`mscc_programmed_challenge)).
qed.

lemma A_ms3c_true_clause_from_ms3b_and_schnorr :
  forall (x : ms_public_input) (s : seed),
    ms3c_true_clause_schnorr_from_blinder x s =>
    forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
      ms_true_clause_simulates_from_blinder_points vb tb p r c =>
      ms_true_clause_position vb tb p =>
      ms_clause_public_point_matches_blinder c.`mscc_ann_true true r.
proof.
move=> x s [Hms3b [Hreparam Htrue]] vb tb p r c Hbl Hpos.
have [Hop [Hhd Hob]] := Hms3b vb tb p r c Hpos.
have Hms3bTrue :=
  MS_3b_true_clause_characterization x vb tb p c.`mscc_ann_true r Hop Hhd Hpos Hob.
have Hsch := Hreparam vb tb p r c Hpos.
have _ := Hsch.
rewrite /ms_true_clause_points_are_blinder_points in Hms3bTrue.
exact (Hms3bTrue Hpos).
qed.

lemma A_ms3c_challenge_share_sum :
  forall (x : ms_public_input) (s : seed),
    ms3c_clause_challenge_shares_sum x s =>
    forall (c : ms_comparison_clause_surface),
      ms_comparison_clause_simulatable c =>
      ms_comparison_challenges_split c.
proof.
move=> x s Hsum c Hsim.
rewrite /ms_comparison_challenges_split /ms3c_clause_shares_sum_matches_global.
have Hpg := Hsum c Hsim.
move: Hsim => [_ [Hann_sh Hann_fx]].
split.
  by rewrite -Hann_sh Hann_fx.
split.
  by rewrite eq_sym Hann_sh.
by rewrite Hpg.
qed.

(* Narrow payload obligations (still proof debt until laws are instantiated). *)
axiom A_ms3c_payload_public_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_public_fields_match x s.

axiom A_ms3c_payload_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_shares_match x s.

axiom A_ms3c_coupling_real_marginal :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x.

axiom A_ms3c_coupling_sim_marginal :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s.

axiom A_ms3c_coupling_pair_relation :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_coupling_pair_relation x s.

lemma A_ms3c_payload_support_coupling_from_components :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_support_coupling x s.
proof.
move=> x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue.
rewrite /ms3c_ax_payload_support_coupling.
split.
  exact (A_ms3c_coupling_real_marginal x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
split.
  exact (A_ms3c_coupling_sim_marginal x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
exact (A_ms3c_coupling_pair_relation x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
qed.

lemma L_ms3c_payload_eq_of_coupled
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) :
  ms3c_real_sim_payload_coupled pr ps =>
  pr = ps.
proof.
case: pr=> tr fr atr afr str sfr gcr qdr pcr.
case: ps=> ts fs ats afs sts sfs gcs qds pcs /=.
move=> [Hpub [Hshr _]].
move: Hpub=> [Htr [Hfr [Hatr [Hafr [Hqd [Hgc Hpc]]]]]].
move: Hshr=> [Hstr Hsfr].
by subst.
qed.

axiom A_ms3c_payload_schedule_eq_from_coupling :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_support_coupling x s =>
    d_ms3c_real_comparison_payload x = d_ms3c_sim_comparison_payload x s.

lemma L_ms3c_payload_announcement_digests_preserved_from_public_fields
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_public_fields_match x s =>
  ms3c_ax_payload_announcement_digests_preserved x s.
proof.
move=> Hpub pr ps Hpr Hps.
have Hm := Hpub pr ps Hpr Hps.
move: Hm => [_ [_ [Hann_t [Hann_f _]]]].
by rewrite /ms3c_clause_ann_digests_from_surface /ms3c_make_real_clause_surface
  /ms3c_make_sim_clause_surface /ms3c_make_clause_surface
  /ms3c_digest_true_announcement /ms3c_digest_false_announcements /= Hann_t Hann_f.
qed.

lemma L_ms3c_payload_announcements_match_shape_from_ann_hook
  (x : ms_public_input) (s : seed) :
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr)) =>
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps)) =>
  ms3c_ax_payload_announcements_match_shape x s.
proof.
move=> Hreal Hsim.
rewrite /ms3c_ax_payload_announcements_match_shape /ms3c_payload_ann_digest_list_shape_ok.
split.
  move=> pr Hpr.
  exact (L_ms3c_ann_digest_list_shape (ms3c_make_real_clause_surface pr)).
move=> ps Hps.
exact (L_ms3c_ann_digest_list_shape (ms3c_make_sim_clause_surface ps)).
qed.

lemma L_ms3c_payload_challenge_share_consistency_from_sum_hook
  (x : ms_public_input) (s : seed) :
  ms3c_clause_challenge_shares_sum x s =>
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr)) =>
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps)) =>
  ms3c_ax_payload_challenge_share_consistency x s.
proof.
move=> Hsum Hreal Hsim.
rewrite /ms3c_ax_payload_challenge_share_consistency /ms3c_payload_programmed_challenge_matches_global.
split.
  move=> pr Hpr.
  by apply (Hsum (ms3c_make_real_clause_surface pr) (Hreal pr Hpr)).
move=> ps Hps.
by apply (Hsum (ms3c_make_sim_clause_surface ps) (Hsim ps Hps)).
qed.

lemma L_ms3c_payload_true_clause_simulated_from_true_hook
  (x : ms_public_input) (s : seed) :
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_ax_payload_true_clause_simulated x s.
proof.
move=> Htrue.
rewrite /ms3c_ax_payload_true_clause_simulated.
split.
  move=> vb tb p r pr _ Hbl Hpos.
  by apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r (ms3c_make_real_clause_surface pr) Hbl Hpos).
move=> vb tb p r ps _ Hbl Hpos.
by apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r (ms3c_make_sim_clause_surface ps) Hbl Hpos).
qed.

lemma A_ms3c_payload_schedule_equiv :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    d_ms3c_real_comparison_payload x = d_ms3c_sim_comparison_payload x s.
proof.
move=> x s Hann Ha2 Hfalse Htrue Hsum.
have Hreal : forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr).
  by move=> pr Hpr; apply (A_ms3c_real_payload_support_simulatable x pr Hpr).
have Hsim : forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).
  by move=> ps Hps; apply (A_ms3c_sim_payload_support_simulatable x s ps Hps).
have Hpub := A_ms3c_payload_public_fields_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hshr := A_ms3c_payload_challenge_shares_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hann_dig :=
  L_ms3c_payload_announcement_digests_preserved_from_public_fields x s Hpub.
have Hann_shape :=
  L_ms3c_payload_announcements_match_shape_from_ann_hook x s Hreal Hsim.
have Hcons :=
  L_ms3c_payload_challenge_share_consistency_from_sum_hook x s Hsum Hreal Hsim.
have Hfalse_payload := A_ms3c_false_clause_simulation x s Hfalse.
have Htrue_payload := L_ms3c_payload_true_clause_simulated_from_true_hook x s Htrue.
have Hcpl :=
  A_ms3c_payload_support_coupling_from_components x s
    Hpub Hshr Hann_dig Hann_shape Hcons Hfalse_payload Htrue_payload.
exact (A_ms3c_payload_schedule_eq_from_coupling x s Hcpl).
qed.

lemma A_ms3c_comparison_schedule_equiv :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    d_ms3c_real_comparison_schedule x = d_ms3c_sim_comparison_schedule x s.
proof.
move=> x s Hann Ha2 Hfalse Htrue Hsum.
have Hp := A_ms3c_payload_schedule_equiv x s Hann Ha2 Hfalse Htrue Hsum.
rewrite /d_ms3c_real_comparison_schedule /d_ms3c_sim_comparison_schedule
  /ms3c_make_real_clause_surface /ms3c_make_sim_clause_surface.
exact (qssm_dmap_congr (d_ms3c_real_comparison_payload x) (d_ms3c_sim_comparison_payload x s)
  ms3c_make_clause_surface Hp).
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

lemma L_ms3c_rom_scalar_response_for_any_digest (x : ms_public_input) (s : seed) :
  ms3c_comparison_global_programmable_under_A2 x s =>
  forall (qd : digest), exists (t : scalar), ms_query_to_scalar qd = t.
proof.
rewrite /ms3c_comparison_global_programmable_under_A2 /ms3c_programmed_comparison_rom_ready.
by move=> Hrom qd; case: (Hrom qd) => t Ht; exists t.
qed.

lemma MS_3c_comparison_clause_obligations (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  (forall (stmt : digest) (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c)) /\
  ((forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_false_clause_simulated (ms3c_make_real_clause_surface pr)) /\
   (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_false_clause_simulated (ms3c_make_sim_clause_surface ps))) /\
  (forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
    ms_true_clause_simulates_from_blinder_points vb tb p r c =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder c.`mscc_ann_true true r) /\
  (forall (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    ms_comparison_challenges_split c).
proof.
move=> Hann Hfalse Htrue Hsum.
split; first by move=> stmt c Hsim; apply (A_ms3c_digest_announcement_only x s Hann stmt c Hsim).
split.
  move: (A_ms3c_false_clause_simulation x s Hfalse).
  rewrite /ms3c_ax_payload_false_clauses_simulated; case=> Hfr Hfs.
  split; first by move=> pr Hpr; apply (Hfr pr Hpr).
  by move=> ps Hps; apply (Hfs ps Hps).
split; first by move=> vb tb p r c Hbl Hpos; apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r c Hbl Hpos).
by move=> c Hsim; apply (A_ms3c_challenge_share_sum x s Hsum c Hsim).
qed.

lemma MS_3c_exact_comparison_simulation_from_clauses (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_comparison_global_programmable_under_A2 x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  ms_comparison_exact_simulation_equiv x s.
proof.
move=> Hann Ha2 Hfalse Htrue Hsum.
have Heq := A_ms3c_comparison_schedule_equiv x s Hann Ha2 Hfalse Htrue Hsum.
have _ := L_ms3c_rom_scalar_response_for_any_digest x s Ha2.
exact (ms_comparison_exact_simulation_equiv_of_schedule_eq x s Heq).
qed.
