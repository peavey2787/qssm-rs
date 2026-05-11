require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require export SourceTypes.

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

(* Payload records: scheduling carriers before folding into `ms_comparison_clause_surface`.
   Payload-only sampled-coin fields are ignored by `ms3c_make_clause_surface`, so the
   coupling layer can remain surface-oriented while lower layers expose sampled ROM /
   transcript state end to end. *)
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
  mscp_rom_coin : scalar;
  mscp_transcript_coin : scalar;
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

(* Ordered announcement digest material (true branch first, then false branches).
   Lives in `ComparisonTypes` so Phase-1 `from_seed` can hash without importing
   `ComparisonDigests` (acyclic module order). *)
op ms3c_digest_true_announcement (a : sch_point) : digest =
  ms_single_bit_branch_digest a.

op ms3c_digest_false_announcements (anns : sch_point list) : digest list =
  map ms_single_bit_branch_digest anns.

op ms3c_clause_ann_digests_from_surface (c : ms_comparison_clause_surface) : digest list =
  ms3c_digest_true_announcement c.`mscc_ann_true :: ms3c_digest_false_announcements c.`mscc_ann_false.

op ms3c_clause_ann_digests (c : ms_comparison_clause_surface) : digest list =
  ms3c_clause_ann_digests_from_surface c.

(* Inverse of `ms3c_make_clause_surface` (definitional bijection on carriers). *)
op ms3c_clause_surface_to_payload (c : ms_comparison_clause_surface) : ms3c_comparison_clause_payload =
  {| mscp_true_clause_ix = c.`mscc_true_clause_ix;
     mscp_false_clause_ixs = c.`mscc_false_clause_ixs;
     mscp_ann_true = c.`mscc_ann_true;
     mscp_ann_false = c.`mscc_ann_false;
     mscp_share_true = c.`mscc_share_true;
     mscp_share_false = c.`mscc_share_false;
     mscp_global_challenge = c.`mscc_global_challenge;
     mscp_query_digest = c.`mscc_query_digest;
  mscp_programmed_challenge = c.`mscc_programmed_challenge;
  mscp_rom_coin = ms_query_to_scalar c.`mscc_query_digest;
  mscp_transcript_coin = c.`mscc_share_true |}.

lemma L_ms3c_make_clause_surface_clause_surface_to_payload (c : ms_comparison_clause_surface) :
  ms3c_make_clause_surface (ms3c_clause_surface_to_payload c) = c.
proof.
by rewrite /ms3c_make_clause_surface /ms3c_clause_surface_to_payload; case: c.
qed.

op ms3c_make_real_clause_surface (p : ms3c_real_comparison_payload) : ms_comparison_clause_surface =
  ms3c_make_clause_surface p.

op ms3c_make_sim_clause_surface (p : ms3c_sim_comparison_payload) : ms_comparison_clause_surface =
  ms3c_make_clause_surface p.

(* MS-3c projection surface: bridge concrete `ms_public_input` and the
   MS observable to the comparison payload lane.

   The public carrier now provides a native comparison slice (true-clause index
   plus indexed false openings), and the observable carries native comparison
   openings directly. Canonical comparison statement digest for ROM query
   hashing remains `ms3c_public_stmt_digest x` (single source of truth).
   `ms3c_comparison_stmt_digest` aliases it so legacy call sites stay aligned. *)

op ms3c_public_stmt_digest (x : ms_public_input) : digest = x.`mspi_stmt_digest.

op ms3c_comparison_stmt_digest (x : ms_public_input) : digest = ms3c_public_stmt_digest x.

op ms3c_public_slice (x : ms_public_input) : ms_comparison_slice =
  ms_public_comparison_slice x.

op ms3c_public_true_opening (x : ms_public_input) : ms_comparison_opening =
  ms_public_comparison_true_opening x.

op ms3c_public_false_openings (x : ms_public_input) : ms_comparison_opening list =
  ms_public_comparison_false_openings x.

op ms3c_public_false_branch_count (x : ms_public_input) : int =
  size (ms_public_comparison_false_entries x).

op ms3c_public_true_clause_index (x : ms_public_input) : int =
  ms_public_comparison_true_clause_index x.

op ms3c_public_false_clause_indices (x : ms_public_input) : int list =
  ms_public_comparison_false_indices x.

op ms3c_public_true_share (x : ms_public_input) : scalar =
  (ms3c_public_true_opening x).`2.

op ms3c_public_true_announcement (x : ms_public_input) : sch_point =
  (ms3c_public_true_opening x).`1.

op ms3c_public_false_shares (x : ms_public_input) : scalar list =
  map (fun (opening : ms_comparison_opening) => opening.`2)
    (ms3c_public_false_openings x).

op ms3c_public_false_announcements (x : ms_public_input) : sch_point list =
  map (fun (opening : ms_comparison_opening) => opening.`1)
    (ms3c_public_false_openings x).

op ms3c_obs_openings (obs : ms_transcript_observable) : ms_comparison_openings =
  obs.`msv2_comparison_openings.

op ms3c_obs_true_opening (obs : ms_transcript_observable) : ms_comparison_opening =
  (ms3c_obs_openings obs).`mscos_true_opening.

op ms3c_obs_false_openings (obs : ms_transcript_observable) : ms_comparison_opening list =
  (ms3c_obs_openings obs).`mscos_false_openings.

op ms3c_obs_programmed_challenge (obs : ms_transcript_observable) : digest =
  obs.`msv2_comparison_global_challenge.

op ms3c_obs_share_true (obs : ms_transcript_observable) : scalar =
  (ms3c_obs_true_opening obs).`2.

op ms3c_obs_shares_false (obs : ms_transcript_observable) : scalar list =
  map (fun (opening : ms_comparison_opening) => opening.`2)
    (ms3c_obs_false_openings obs).

op ms3c_obs_ann_true (obs : ms_transcript_observable) : sch_point =
  (ms3c_obs_true_opening obs).`1.

op ms3c_obs_anns_false (obs : ms_transcript_observable) : sch_point list =
  map (fun (opening : ms_comparison_opening) => opening.`1)
    (ms3c_obs_false_openings obs).

(* Strict positivity of public false-branch arity (comparison has ≥1 false clause). *)
pred ms3c_public_false_branch_nonempty (x : ms_public_input) =
  0 < ms3c_public_false_branch_count x.

pred ms3c_public_shape_ok (x : ms_public_input) =
  0 <= ms3c_public_true_clause_index x /\
  size (ms3c_public_false_announcements x) = size (ms3c_public_false_clause_indices x).

lemma L_ms3c_public_shape_ok_of_native_slice (x : ms_public_input) :
  ms3c_public_shape_ok x.
proof.
rewrite /ms3c_public_shape_ok /ms3c_public_true_clause_index.
rewrite /ms_public_comparison_true_clause_index /ms_public_comparison_true_clause_index_raw.
split.
- by case: (0 <= (ms_public_comparison_slice x).`mscs_true_clause_ix).
rewrite /ms3c_public_false_announcements /ms3c_public_false_clause_indices.
rewrite /ms3c_public_false_openings /ms_public_comparison_false_openings.
rewrite /ms_public_comparison_false_indices /ms_public_comparison_false_entries.
by rewrite !size_map.
qed.

pred ms3c_observable_shape_ok (x : ms_public_input) (obs : ms_transcript_observable) =
  ms3c_public_shape_ok x /\
  size (ms3c_obs_shares_false obs) = ms3c_public_false_branch_count x /\
  size (ms3c_obs_anns_false obs) = ms3c_public_false_branch_count x.

pred ms3c_public_false_openings_simulated (x : ms_public_input) =
  forall (i : int), 0 <= i => i < size (ms3c_public_false_announcements x) =>
    nth witness (ms3c_public_false_announcements x) i =
      sch_pubkey (nth witness (ms3c_public_false_shares x) i).

pred ms_comparison_clause_simulatable (c : ms_comparison_clause_surface) =
  0 <= c.`mscc_true_clause_ix /\
  size c.`mscc_ann_false = size c.`mscc_share_false /\
  size c.`mscc_ann_false = size c.`mscc_false_clause_ixs.

lemma L_ms3c_comparison_clause_simulatable_make_surface_to_payload (c : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable (ms3c_make_clause_surface (ms3c_clause_surface_to_payload c)) <=>
  ms_comparison_clause_simulatable c.
proof.
rewrite L_ms3c_make_clause_surface_clause_surface_to_payload.
by [].
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

pred ms3c_programmed_comparison_rom_ready (x : ms_public_input) (s : seed) =
  forall (qd : digest), exists (t : scalar), ms_query_to_scalar qd = t.

pred ms3c_comparison_global_programmable_under_A2 (x : ms_public_input) (s : seed) =
  ms3c_programmed_comparison_rom_ready x s.

pred ms3c_false_clauses_simulator_generated (x : ms_public_input) (s : seed) =
  ms3c_public_false_branch_nonempty x /\
  ms3c_public_false_openings_simulated x.

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
