require import AllCore Int List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClauseTypes BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.

(* Phase-1 structural payload and dmap pushforwards; cross-marginal payload
   equality on support; schedule/surface packaging. *)

op ms3c_phase1_comparison_carrier_from_public_input (x : ms_public_input) :
  ms3b_concrete_comparison_carrier =
  ms3b_phase1_comparison_carrier x.

op ms3c_payload_from_seed_components
  (sc : ms3c_seed_challenge) (sa : ms3c_seed_announcement) :
  ms3c_comparison_clause_payload =
  {| mscp_true_clause_ix = sc.`ms3csc_true_clause_ix;
     mscp_false_clause_ixs = sc.`ms3csc_false_clause_ixs;
     mscp_ann_true = sa.`ms3csa_ann_true;
     mscp_ann_false = sa.`ms3csa_ann_false;
     mscp_share_true = sc.`ms3csc_share_true;
     mscp_share_false = sc.`ms3csc_share_false;
     mscp_global_challenge = sc.`ms3csc_global_challenge;
     mscp_query_digest = sc.`ms3csc_query_digest;
     mscp_programmed_challenge = sc.`ms3csc_programmed_challenge |}.

(* Phase-1 structural payload: the native comparison slice on `ms_public_input`
  now carries the real false-branch arity/index data and native openings.
  The payload uses those openings directly instead of deriving them from
  transcript or comparison digests. *)
op ms3c_phase1_payload_from_public_input (x : ms_public_input) : ms3c_comparison_clause_payload =
  ms3c_payload_from_seed_components
    (ms3c_phase1_seed_challenge_from_public_input x)
    (ms3c_phase1_seed_announcement_from_public_input x).

lemma L_ms3c_phase1_payload_uses_ms3b_carrier (x : ms_public_input) :
  (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_ix /\
  (ms3c_phase1_payload_from_public_input x).`mscp_ann_true =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_pub /\
  (ms3c_phase1_payload_from_public_input x).`mscp_share_true =
    (ms3c_phase1_comparison_carrier_from_public_input x).`ms3bc_true_clause_blinder.
proof.
rewrite /ms3c_phase1_payload_from_public_input /ms3c_payload_from_seed_components.
rewrite /ms3c_phase1_seed_challenge_from_public_input /ms3c_phase1_seed_announcement_from_public_input.
rewrite /ms3c_seed_challenge_with_rom_coin /ms3c_seed_announcement_with_transcript_coin.
rewrite /ms3c_public_true_clause_index /ms3c_public_true_announcement /ms3c_public_true_share.
by rewrite /ms3c_phase1_comparison_carrier_from_public_input /ms3b_phase1_comparison_carrier.
qed.

lemma L_ms3c_phase1_payload_uses_concrete_public_surface (x : ms_public_input) :
  (ms3c_phase1_payload_from_public_input x).`mscp_ann_false = ms3c_public_false_announcements x /\
  (ms3c_phase1_payload_from_public_input x).`mscp_share_false = ms3c_public_false_shares x /\
  (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge = x.`mspi_comparison_global /\
  (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge = x.`mspi_comparison_global.
proof.
rewrite /ms3c_phase1_payload_from_public_input /ms3c_payload_from_seed_components.
rewrite /ms3c_phase1_seed_challenge_from_public_input /ms3c_phase1_seed_announcement_from_public_input.
rewrite /ms3c_seed_challenge_with_rom_coin /ms3c_seed_announcement_with_transcript_coin.
by rewrite /ms3c_public_false_announcements /ms3c_public_false_shares.
qed.

lemma L_ms3c_int_lt1_eq0 (i : int) : 0 <= i => i < 1 => i = 0.
proof.
move=> ge0 lt1.
rewrite ltz1 in lt1.
by rewrite eqz_leq; split=> //.
qed.

lemma L_ms_false_clause_simulated_phase1_from_public_input (x : ms_public_input) :
  ms3c_public_false_openings_simulated x =>
  ms_false_clause_simulated (ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x)).
proof.
move=> Hsim.
rewrite /ms_false_clause_simulated /ms3c_make_clause_surface.
rewrite /ms3c_phase1_payload_from_public_input /ms3c_payload_from_seed_components.
rewrite /ms3c_phase1_seed_challenge_from_public_input /ms3c_phase1_seed_announcement_from_public_input.
rewrite /ms3c_seed_challenge_with_rom_coin /ms3c_seed_announcement_with_transcript_coin /=.
exact Hsim.
qed.

op ms3c_real_payload_from_seed (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  ms3c_real_comparison_payload =
  ms3c_payload_from_seed_components sr.`1 sr.`2.

op ms3c_sim_payload_from_seed (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ms3c_sim_comparison_payload =
  ms3c_payload_from_seed_components ss.`1 ss.`2.

lemma L_ms3c_real_payload_from_seed_support_phase1_fields
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix =
    (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix /\
  (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs =
    (ms3c_phase1_payload_from_public_input x).`mscp_false_clause_ixs /\
  (ms3c_real_payload_from_seed x sr).`mscp_ann_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_true /\
  (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_false /\
  (ms3c_real_payload_from_seed x sr).`mscp_share_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_true /\
  (ms3c_real_payload_from_seed x sr).`mscp_share_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_false /\
  (ms3c_real_payload_from_seed x sr).`mscp_global_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge /\
  (ms3c_real_payload_from_seed x sr).`mscp_query_digest =
    (ms3c_phase1_payload_from_public_input x).`mscp_query_digest /\
  (ms3c_real_payload_from_seed x sr).`mscp_programmed_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge.
proof.
move=> Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [Hsc Hsa].
have [_ [Htrue_ix [Hfalse_ixs [Hshare_true [Hshare_false [Hglob [Hprog Hquery]]]]]]]
  := L_ms3c_real_seed_challenge_on_support_public_surface x sc Hsc.
have [Hann_true Hann_false] :=
  L_ms3c_real_seed_announcement_on_support_public_surface x sa Hsa.
rewrite /ms3c_real_payload_from_seed /ms3c_phase1_payload_from_public_input
  /ms3c_payload_from_seed_components /=.
rewrite Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
by smt.
qed.

lemma L_ms3c_sim_payload_from_seed_support_phase1_fields
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix =
    (ms3c_phase1_payload_from_public_input x).`mscp_true_clause_ix /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs =
    (ms3c_phase1_payload_from_public_input x).`mscp_false_clause_ixs /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_ann_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_true /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_ann_false /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_share_true =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_true /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_share_false =
    (ms3c_phase1_payload_from_public_input x).`mscp_share_false /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_global_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_global_challenge /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_query_digest =
    (ms3c_phase1_payload_from_public_input x).`mscp_query_digest /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_programmed_challenge =
    (ms3c_phase1_payload_from_public_input x).`mscp_programmed_challenge.
proof.
move=> Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [Hsc Hsa].
have [_ [Htrue_ix [Hfalse_ixs [Hshare_true [Hshare_false [Hglob [Hprog Hquery]]]]]]]
  := L_ms3c_sim_seed_challenge_on_support_public_surface x s sc Hsc.
have [Hann_true Hann_false] :=
  L_ms3c_sim_seed_announcement_on_support_public_surface x s sa Hsa.
rewrite /ms3c_sim_payload_from_seed /ms3c_phase1_payload_from_public_input
  /ms3c_payload_from_seed_components /=.
rewrite Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
by smt.
qed.

lemma L_ms3c_real_payload_from_seed_on_support_eq_phase1
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  ms3c_real_payload_from_seed x sr = ms3c_phase1_payload_from_public_input x.
proof.
move=> Hsr.
have [Htrue_ix [Hfalse_ixs [Hann_true [Hann_false [Hshare_true [Hshare_false [Hglob [Hquery Hprog]]]]]]]]
  := L_ms3c_real_payload_from_seed_support_phase1_fields x sr Hsr.
case: (ms3c_real_payload_from_seed x sr) Htrue_ix Hfalse_ixs Hann_true Hann_false
      Hshare_true Hshare_false Hglob Hquery Hprog.
case: (ms3c_phase1_payload_from_public_input x).
move=> tr fr atr afr str sfr gcr qdr pcr tr0 fr0 atr0 afr0 str0 sfr0 gcr0 qdr0 pcr0 /=.
move=> Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
subst.
by [].
qed.

lemma L_ms3c_sim_payload_from_seed_on_support_eq_phase1
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  ms3c_sim_payload_from_seed x s ss = ms3c_phase1_payload_from_public_input x.
proof.
move=> Hss.
have [Htrue_ix [Hfalse_ixs [Hann_true [Hann_false [Hshare_true [Hshare_false [Hglob [Hquery Hprog]]]]]]]]
  := L_ms3c_sim_payload_from_seed_support_phase1_fields x s ss Hss.
case: (ms3c_sim_payload_from_seed x s ss) Htrue_ix Hfalse_ixs Hann_true Hann_false
      Hshare_true Hshare_false Hglob Hquery Hprog.
case: (ms3c_phase1_payload_from_public_input x).
move=> tr fr atr afr str sfr gcr qdr pcr tr0 fr0 atr0 afr0 str0 sfr0 gcr0 qdr0 pcr0 /=.
move=> Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
subst.
by [].
qed.

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
case/supp_dmap: Hpr => sr [Hsr Heqpr].
case/supp_dmap: Hps => ss [Hss Heqps].
rewrite Heqpr Heqps.
have -> := L_ms3c_real_payload_from_seed_on_support_eq_phase1 x sr Hsr.
have -> := L_ms3c_sim_payload_from_seed_on_support_eq_phase1 x s ss Hss.
by [].
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
