require import AllCore Int List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClauseTypes BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.

(* Phase-1 structural payload and dmap pushforwards; surface-field equalities on
  support plus payload-only sampled-coin propagation and coin-driven auxiliary
  ROM/transcript views; schedule/surface packaging.

  Decision for the current MS-3c lane: the auxiliary ROM/transcript views below
  stay proof-local. They are derived witnesses showing how payload-visible coins
  could feed a richer non-public execution state, but the compared public/share
  surface, schedule operators, and coupling shell still ignore them.

  The first concrete consumer, once integration is needed, should be a
  comparison-side execution-seed package mirroring `SourceRealExecutionSeed.ec`:
  it would consume the auxiliary ROM row and comparison-opening bundle as
  internal execution state while keeping `ms3c_make_clause_surface` unchanged. *)

op ms3c_phase1_comparison_carrier_from_public_input (x : ms_public_input) :
  ms3b_concrete_comparison_carrier =
  ms3b_phase1_comparison_carrier x.

op ms3c_payload_coin_driven_rom_row
  (p : ms3c_comparison_clause_payload) : (digest * scalar) =
  (p.`mscp_query_digest, p.`mscp_rom_coin).

(* Proof-local auxiliary transcript view derived from the payload: it keeps the
   compared announcement projection fixed while threading the transcript coin
  through non-public openings. The intended downstream consumer is a future
  execution-facing comparison seed law, not the current schedule/coupling path. *)
op ms3c_payload_coin_driven_transcript_openings
  (p : ms3c_comparison_clause_payload) : ms_comparison_openings =
  {| mscos_true_opening = (p.`mscp_ann_true, p.`mscp_transcript_coin);
     mscos_false_openings =
       map (fun (ann : sch_point) => (ann, p.`mscp_transcript_coin))
           p.`mscp_ann_false |}.

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
    mscp_programmed_challenge = sc.`ms3csc_programmed_challenge;
    mscp_rom_coin = sc.`ms3csc_rom_coin;
    mscp_transcript_coin = sa.`ms3csa_transcript_coin |}.

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

lemma L_ms3c_real_payload_from_seed_visible_coin_fields
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  (ms3c_real_payload_from_seed x sr).`mscp_rom_coin = sr.`1.`ms3csc_rom_coin /\
  (ms3c_real_payload_from_seed x sr).`mscp_transcript_coin = sr.`2.`ms3csa_transcript_coin.
proof.
move=> Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [_ _].
rewrite /ms3c_real_payload_from_seed /ms3c_payload_from_seed_components /=.
by split.
qed.

lemma L_ms3c_real_payload_from_seed_coin_driven_rom_row
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  ms3c_payload_coin_driven_rom_row (ms3c_real_payload_from_seed x sr) =
    (ms3c_phase1_seed_query_digest x,
     (ms3c_real_payload_from_seed x sr).`mscp_rom_coin).
proof.
move=> Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [Hsc _].
have Hsurf := L_ms3c_real_seed_challenge_on_support_public_surface x sc Hsc.
move: Hsurf => [_ [_ [_ [_ [_ [_ [_ Hquery]]]]]]].
by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components /= Hquery.
qed.

lemma L_ms3c_real_payload_from_seed_coin_driven_transcript_openings
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  ms3c_payload_coin_driven_transcript_openings (ms3c_real_payload_from_seed x sr) =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x,
          (ms3c_real_payload_from_seed x sr).`mscp_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) =>
               (ann, (ms3c_real_payload_from_seed x sr).`mscp_transcript_coin))
             (ms3c_public_false_announcements x) |}.
proof.
move=> Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [_ Hsa].
have [Hann_true Hann_false] :=
  L_ms3c_real_seed_announcement_on_support_public_surface x sa Hsa.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components /= Hann_true Hann_false.
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

lemma L_ms3c_sim_payload_from_seed_visible_coin_fields
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  (ms3c_sim_payload_from_seed x s ss).`mscp_rom_coin = ss.`1.`ms3csc_rom_coin /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_transcript_coin = ss.`2.`ms3csa_transcript_coin.
proof.
move=> Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [_ _].
rewrite /ms3c_sim_payload_from_seed /ms3c_payload_from_seed_components /=.
by split.
qed.

lemma L_ms3c_sim_payload_from_seed_coin_driven_rom_row
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  ms3c_payload_coin_driven_rom_row (ms3c_sim_payload_from_seed x s ss) =
    (ms3c_phase1_seed_query_digest x,
     (ms3c_sim_payload_from_seed x s ss).`mscp_rom_coin).
proof.
move=> Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [Hsc _].
have Hsurf := L_ms3c_sim_seed_challenge_on_support_public_surface x s sc Hsc.
move: Hsurf => [_ [_ [_ [_ [_ [_ [_ Hquery]]]]]]].
by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components /= Hquery.
qed.

lemma L_ms3c_sim_payload_from_seed_coin_driven_transcript_openings
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  ms3c_payload_coin_driven_transcript_openings (ms3c_sim_payload_from_seed x s ss) =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x,
          (ms3c_sim_payload_from_seed x s ss).`mscp_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) =>
               (ann, (ms3c_sim_payload_from_seed x s ss).`mscp_transcript_coin))
             (ms3c_public_false_announcements x) |}.
proof.
move=> Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [_ Hsa].
have [Hann_true Hann_false] :=
  L_ms3c_sim_seed_announcement_on_support_public_surface x s sa Hsa.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components /= Hann_true Hann_false.
qed.

lemma L_ms3c_real_payload_from_seed_on_support_eq_phase1
  (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  ms3c_make_real_clause_surface (ms3c_real_payload_from_seed x sr) =
  ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x).
proof.
move=> Hsr.
have [Htrue_ix [Hfalse_ixs [Hann_true [Hann_false [Hshare_true [Hshare_false [Hglob [Hquery Hprog]]]]]]]]
  := L_ms3c_real_payload_from_seed_support_phase1_fields x sr Hsr.
rewrite /ms3c_make_real_clause_surface /ms3c_make_clause_surface /=.
by rewrite Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
qed.

lemma L_ms3c_sim_payload_from_seed_on_support_eq_phase1
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  ms3c_make_sim_clause_surface (ms3c_sim_payload_from_seed x s ss) =
  ms3c_make_clause_surface (ms3c_phase1_payload_from_public_input x).
proof.
move=> Hss.
have [Htrue_ix [Hfalse_ixs [Hann_true [Hann_false [Hshare_true [Hshare_false [Hglob [Hquery Hprog]]]]]]]]
  := L_ms3c_sim_payload_from_seed_support_phase1_fields x s ss Hss.
rewrite /ms3c_make_sim_clause_surface /ms3c_make_clause_surface /=.
by rewrite Htrue_ix Hfalse_ixs Hann_true Hann_false Hshare_true Hshare_false Hglob Hquery Hprog.
qed.

op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_payload_seed x) (ms3c_real_payload_from_seed x).

op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_payload_seed x s) (ms3c_sim_payload_from_seed x s).

op ms3c_real_payload_from_execution_seed
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms3c_real_comparison_payload =
  ms3c_real_payload_from_seed x (ms3c_real_payload_seed_of_execution_seed sigma).

op ms3c_sim_payload_from_execution_seed
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  ms3c_sim_comparison_payload =
  ms3c_sim_payload_from_seed x s (ms3c_sim_payload_seed_of_execution_seed sigma).

op d_ms3c_real_execution_comparison_payload
  (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_execution_seed x) (ms3c_real_payload_from_execution_seed x).

op d_ms3c_sim_execution_comparison_payload
  (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_execution_seed x s) (ms3c_sim_payload_from_execution_seed x s).

lemma L_ms3c_real_execution_payload_aux_views_match
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  sigma.`ms3cep_rom_row =
    ms3c_payload_coin_driven_rom_row (ms3c_real_payload_from_execution_seed x sigma) /\
  sigma.`ms3cep_transcript_openings =
    ms3c_payload_coin_driven_transcript_openings
      (ms3c_real_payload_from_execution_seed x sigma).
proof.
move=> Hsigma.
have [sr [Hsr ->]] := L_ms3c_real_execution_seed_support_inv x sigma Hsigma.
clear Hsr.
case: sr=> sc sa /=.
rewrite /ms3c_real_payload_from_execution_seed
  /ms3c_real_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_real_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
split.
- by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_real_payload_from_seed
    /ms3c_payload_from_seed_components /ms3c_seed_challenge_coin_driven_rom_row.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components
  /ms3c_seed_announcement_coin_driven_transcript_openings.
qed.

lemma L_ms3c_sim_execution_payload_aux_views_match
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  sigma \in d_ms3c_sim_execution_seed x s =>
  sigma.`ms3cep_rom_row =
    ms3c_payload_coin_driven_rom_row (ms3c_sim_payload_from_execution_seed x s sigma) /\
  sigma.`ms3cep_transcript_openings =
    ms3c_payload_coin_driven_transcript_openings
      (ms3c_sim_payload_from_execution_seed x s sigma).
proof.
move=> Hsigma.
have [ss [Hss ->]] := L_ms3c_sim_execution_seed_support_inv x s sigma Hsigma.
clear Hss.
case: ss=> sc sa /=.
rewrite /ms3c_sim_payload_from_execution_seed
  /ms3c_sim_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
split.
- by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_sim_payload_from_seed
    /ms3c_payload_from_seed_components /ms3c_seed_challenge_coin_driven_rom_row.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components
  /ms3c_seed_announcement_coin_driven_transcript_openings.
qed.

lemma A_ms3c_real_comparison_payload_matches_execution_seed_law
  (x : ms_public_input) :
  d_ms3c_real_comparison_payload x =
  d_ms3c_real_execution_comparison_payload x.
proof.
rewrite /d_ms3c_real_execution_comparison_payload /d_ms3c_real_execution_seed.
rewrite (dmap_comp ms3c_real_execution_seed_of_payload_seed
  (ms3c_real_payload_from_execution_seed x) (d_ms3c_real_payload_seed x)).
apply eq_dmap_in=> sr _ /=.
case: sr=> sc sa /=.
by rewrite /ms3c_real_payload_from_execution_seed
  /ms3c_real_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_real_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma A_ms3c_sim_comparison_payload_matches_execution_seed_law
  (x : ms_public_input) (s : seed) :
  d_ms3c_sim_comparison_payload x s =
  d_ms3c_sim_execution_comparison_payload x s.
proof.
rewrite /d_ms3c_sim_execution_comparison_payload /d_ms3c_sim_execution_seed.
rewrite (dmap_comp ms3c_sim_execution_seed_of_payload_seed
  (ms3c_sim_payload_from_execution_seed x s) (d_ms3c_sim_payload_seed x s)).
apply eq_dmap_in=> ss _ /=.
case: ss=> sc sa /=.
by rewrite /ms3c_sim_payload_from_execution_seed
  /ms3c_sim_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma L_ms3c_real_execution_comparison_payload_law_lossless
  (x : ms_public_input) :
  is_lossless (d_ms3c_real_execution_comparison_payload x).
proof.
by rewrite /d_ms3c_real_execution_comparison_payload; apply dmap_ll;
  apply (L_ms3c_real_execution_seed_law_lossless x).
qed.

lemma L_ms3c_sim_execution_comparison_payload_law_lossless
  (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_execution_comparison_payload x s).
proof.
by rewrite /d_ms3c_sim_execution_comparison_payload; apply dmap_ll;
  apply (L_ms3c_sim_execution_seed_law_lossless x s).
qed.

(* Real and sim payload laws are independent `dmap`s of seeds. Sampled coins now
  survive in payload-only fields and proof-local auxiliary views, but the folded
  comparison surface is still the same Phase-1 image on support. The execution
  consumer that would justify promoting those auxiliary views is a future
  comparison-side execution-seed package, not the current schedule law. *)
lemma L_ms3c_cross_support_real_sim_payload_surface_equal
  (x : ms_public_input) (s : seed)
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) :
  pr \in d_ms3c_real_comparison_payload x =>
  ps \in d_ms3c_sim_comparison_payload x s =>
  ms3c_make_real_clause_surface pr = ms3c_make_sim_clause_surface ps.
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
