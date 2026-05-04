require import AllCore Int List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClauseTypes BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.

(* Phase-1 structural payload and dmap pushforwards; cross-marginal payload
   equality on support; schedule/surface packaging. *)

op ms3c_phase1_comparison_carrier_from_public_input (x : ms_public_input) :
  ms3b_concrete_comparison_carrier =
  ms3b_phase1_comparison_carrier x.

(* Phase-1 structural payload: public indices, false-branch arity from
   `size (ms3c_public_false_clause_indices x)` (equals `ms3c_public_false_branch_count x`
   under `ms3c_public_shape_ok x`); the true branch is derived from the
   comparison-global digest and the false branch from the transcript digest, so
   the payload is concrete even though it is still only a phase-1 derived
   comparison slice. *)
op ms3c_phase1_payload_from_public_input (x : ms_public_input) : ms3c_comparison_clause_payload =
  {| mscp_true_clause_ix = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_ix;
     mscp_false_clause_ixs = ms3c_public_false_clause_indices x;
     mscp_ann_true = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_pub;
     mscp_ann_false = ms3c_public_false_announcements x;
     mscp_share_true = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_blinder;
     mscp_share_false = ms3c_public_false_shares x;
     mscp_global_challenge = x.`mspi_comparison_global;
     mscp_query_digest =
       ms_comparison_query_digest (ms3c_public_stmt_digest x)
         (ms3c_clause_ann_digests_from_surface
           (ms3c_make_clause_surface
             {| mscp_true_clause_ix = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_ix;
                mscp_false_clause_ixs = ms3c_public_false_clause_indices x;
                mscp_ann_true = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_pub;
                mscp_ann_false = ms3c_public_false_announcements x;
                mscp_share_true = (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_blinder;
                mscp_share_false = ms3c_public_false_shares x;
                mscp_global_challenge = x.`mspi_comparison_global;
                mscp_query_digest = witness;
                mscp_programmed_challenge = x.`mspi_comparison_global |}));
     mscp_programmed_challenge = x.`mspi_comparison_global |}.

lemma L_ms3c_phase1_payload_uses_ms3b_carrier (x : ms_public_input) :
  (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_ix /\
  (ms3c_phase1_payload_from_public_input x).`mscp_ann_true =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_pub /\
  (ms3c_phase1_payload_from_public_input x).`mscp_share_true =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_blinder.
proof.
by rewrite /ms3c_phase1_payload_from_public_input /ms3c_phase1_comparison_carrier_from_public_input.
qed.

lemma L_ms3c_phase1_payload_uses_concrete_public_surface (x : ms_public_input) :
  (ms3c_phase1_payload_from_public_input x).`mscp_ann_false = ms3c_public_false_announcements x /\
  (ms3c_phase1_payload_from_public_input x).`mscp_share_false = ms3c_public_false_shares x /\
  (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge = x.`mspi_comparison_global /\
  (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge = x.`mspi_comparison_global.
proof.
by rewrite /ms3c_phase1_payload_from_public_input.
qed.

lemma L_ms3c_int_lt1_eq0 (i : int) : 0 <= i => i < 1 => i = 0.
proof.
move=> ge0 lt1.
rewrite ltz1 in lt1.
by rewrite eqz_leq; split=> //.
qed.

lemma L_ms_false_clause_simulated_phase1_from_public_input (x : ms_public_input) :
  ms_false_clause_simulated (ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x)).
proof.
rewrite /ms_false_clause_simulated /ms3c_make_clause_surface /ms3c_phase1_payload_from_public_input /=.
have Hix : ms3c_public_false_clause_indices x = [0] by trivial.
move=> i Hi_lo Hi_hi.
have sz1 : size (ms3c_public_false_announcements x) = 1 by trivial.
have hi1 : i < 1.
  rewrite -sz1.
  exact Hi_hi.
have i0 : i = 0 by apply (L_ms3c_int_lt1_eq0 i Hi_lo hi1).
rewrite /ms3c_public_false_announcements /ms3c_public_false_shares Hix /= i0.
by [].
qed.

op ms3c_real_payload_from_seed (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  ms3c_real_comparison_payload =
  ms3c_phase1_payload_from_public_input x.

op ms3c_sim_payload_from_seed (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ms3c_sim_comparison_payload =
  ms3c_phase1_payload_from_public_input x.

op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_payload_seed x) (ms3c_real_payload_from_seed x).

op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_payload_seed x s) (ms3c_sim_payload_from_seed x s).

(* Real and sim payload laws are independent `dmap`s of seeds, but Phase-1
   `from_seed` ignores seeds: every support point is the same
   `ms3c_phase1_payload_from_public_input x`, hence cross-marginal equality. *)
lemma L_ms3c_cross_support_real_sim_payload_equal
  (x : ms_public_input) (s : seed)
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) :
  pr \in d_ms3c_real_comparison_payload x =>
  ps \in d_ms3c_sim_comparison_payload x s =>
  pr = ps.
proof.
move=> Hpr Hps.
case/supp_dmap: Hpr => sr [_ Heqpr].
case/supp_dmap: Hps => ss [_ Heqps].
by rewrite Heqpr Heqps /ms3c_real_payload_from_seed /ms3c_sim_payload_from_seed.
qed.

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

op d_ms3c_comparison_real_clause (x : ms_public_input) : ms_comparison_clause_surface distr =
  d_ms3c_real_comparison_schedule x.

op d_ms3c_comparison_sim_clause (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  d_ms3c_sim_comparison_schedule x s.

pred ms_comparison_exact_simulation_equiv (x : ms_public_input) (s : seed) =
  d_ms3c_comparison_real_clause x = d_ms3c_comparison_sim_clause x s.
