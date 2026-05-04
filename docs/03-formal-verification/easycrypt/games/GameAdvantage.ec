require import AllCore List.
require import Ring.
require import Algebra.
require import QssmTypes.
require import Simulator.
require import GameTypes.
require import GameViews.
require import TranscriptObservable.
require import SourceModel.
require import SourceDistributions.
require import SourceTheorem.
require import MSProbabilitySurface.
require import TrueClause ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayloadFromSeed.
require import MS FS LESurface.

(* Game probability is projected from the concrete `game_view` surface.
  For MS views, the projection first collapses AfterComparison and Sim
  whenever the MS3c exact-simulation bundle holds, then collapses AfterBitness
  and AfterComparison whenever the MS3b true-clause characterization holds,
  then collapses AfterRom and AfterBitness whenever
  `ms3a_bitness_real_sim_equiv` holds. This is enough to prove the canonical
  MS3a/MS3b/MS3c game hops as exact zero-advantage lemmas without adding new
  axioms. *)
pred ms3b_true_clause_game_pr_equiv (xms : ms_public_input) =
  forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
    ms3b_comparison_operand_bits xms vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms_true_clause_position vb tb p =>
    ms3b_clause_opening_binds xms vb tb p clause_pub r =>
    ms_true_clause_points_are_blinder_points vb tb p clause_pub r.

pred ms3c_comparison_game_pr_equiv (xms : ms_public_input) (s : seed) =
  ms3c_comparison_query_digest_ann_only xms s =>
  ms3c_comparison_global_programmable_under_A2 xms s =>
  ms3c_false_clauses_simulator_generated xms s =>
  ms3c_true_clause_schnorr_from_blinder xms s =>
  ms3c_clause_challenge_shares_sum xms s =>
  ms_comparison_exact_simulation_equiv xms s.

lemma L_ms3c_obs_true_share_public_obs (xms : ms_public_input) :
  ms3c_obs_share_true (ms_game_view_public_obs xms) =
  (ms_public_comparison_true_opening xms).`2.
proof.
case: xms=> mspi_stmt_digest mspi_result_bit mspi_bits mspi_comparison_slice
  mspi_comparison_global mspi_transcript_digest /=.
case: mspi_comparison_slice=> mscs_true_clause_ix mscs_true_opening mscs_false_entries /=.
rewrite /ms_game_view_public_obs /ms3a_public_v2_observable /ms3a_public_comparison_openings.
rewrite /ms3c_obs_share_true /ms3c_obs_openings /ms3c_obs_true_opening.
rewrite /ms_public_comparison_true_opening /ms_public_comparison_slice /=.
by smt.
qed.

lemma L_ms3c_obs_true_ann_public_obs (xms : ms_public_input) :
  ms3c_obs_ann_true (ms_game_view_public_obs xms) =
  (ms_public_comparison_true_opening xms).`1.
proof.
case: xms=> mspi_stmt_digest mspi_result_bit mspi_bits mspi_comparison_slice
  mspi_comparison_global mspi_transcript_digest /=.
case: mspi_comparison_slice=> mscs_true_clause_ix mscs_true_opening mscs_false_entries /=.
rewrite /ms_game_view_public_obs /ms3a_public_v2_observable /ms3a_public_comparison_openings.
rewrite /ms3c_obs_ann_true /ms3c_obs_openings /ms3c_obs_true_opening.
rewrite /ms_public_comparison_true_opening /ms_public_comparison_slice /=.
by smt.
qed.

lemma L_ms3c_obs_programmed_public_obs (xms : ms_public_input) :
  ms3c_obs_programmed_challenge (ms_game_view_public_obs xms) =
  xms.`mspi_comparison_global.
proof.
by rewrite /ms_game_view_public_obs /ms3a_public_v2_observable /ms3c_obs_programmed_challenge.
qed.

lemma L_ms3c_obs_global_public_obs (xms : ms_public_input) :
  ms_comparison_global_challenge (ms_game_view_public_obs xms) =
  xms.`mspi_comparison_global.
proof.
by rewrite /ms_game_view_public_obs /ms3a_public_v2_observable /ms_comparison_global_challenge.
qed.

lemma L_ms3c_obs_shares_false_public_obs (xms : ms_public_input) :
  ms3c_obs_shares_false (ms_game_view_public_obs xms) =
  ms3c_public_false_shares xms.
proof.
by rewrite /ms_game_view_public_obs /ms3a_public_v2_observable
  /ms3c_obs_shares_false /ms3c_obs_false_openings /ms3c_obs_openings
  /ms3a_public_comparison_openings /ms3c_public_false_shares
  /ms3c_public_false_openings.
qed.

lemma L_ms3c_obs_anns_false_public_obs (xms : ms_public_input) :
  ms3c_obs_anns_false (ms_game_view_public_obs xms) =
  ms3c_public_false_announcements xms.
proof.
by rewrite /ms_game_view_public_obs /ms3a_public_v2_observable
  /ms3c_obs_anns_false /ms3c_obs_false_openings /ms3c_obs_openings
  /ms3a_public_comparison_openings /ms3c_public_false_announcements
  /ms3c_public_false_openings.
qed.

lemma L_ms3c_game_view_public_obs_aligns_v2 (xms : ms_public_input) :
  ms_abstract_observable_aligns_v2 (ms_game_view_public_obs xms)
    (ms3a_public_v2_observable xms).
proof.
have Halign := A_ms3a_observable_of_v2_aligns (ms3a_public_v2_observable xms).
rewrite /ms_game_view_public_obs /ms3a_observable_of_v2 in Halign.
exact Halign.
qed.

lemma L_ms3c_public_obs_seed_alignment (xms : ms_public_input) :
  let obs = ms_game_view_public_obs xms in
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_stmt_digest =
    ms_statement_digest obs /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_true_clause_ix =
    ms3c_public_true_clause_index xms /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_false_clause_ixs =
    ms3c_public_false_clause_indices xms /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_share_true =
    ms3c_obs_share_true obs /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_share_false =
    ms3c_obs_shares_false obs /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_global_challenge =
    ms_comparison_global_challenge obs /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_programmed_challenge =
    ms3c_obs_programmed_challenge obs /\
  (ms3c_phase1_seed_challenge_from_public_input xms).`ms3csc_query_digest =
    ms3c_phase1_seed_query_digest xms /\
  (ms3c_phase1_seed_announcement_from_public_input xms).`ms3csa_ann_true =
    ms3c_obs_ann_true obs /\
  (ms3c_phase1_seed_announcement_from_public_input xms).`ms3csa_ann_false =
    ms3c_obs_anns_false obs.
proof.
rewrite /=.
have [Hstmt [Htrue_ix [Hfalse_ixs [Hshare_true [Hshare_false [Hglob [Hprog Hquery]]]]]]]
  := L_ms3c_phase1_seed_challenge_uses_public_surface xms.
have [Hann_true Hann_false] :=
  L_ms3c_phase1_seed_announcement_uses_public_surface xms.
split.
- rewrite /ms_game_view_public_obs /ms_statement_digest /ms3a_public_v2_observable
          /ms3c_public_stmt_digest /=.
  exact Hstmt.
split; first exact Htrue_ix.
split; first exact Hfalse_ixs.
split; first by rewrite (L_ms3c_obs_true_share_public_obs xms); exact Hshare_true.
split; first by rewrite (L_ms3c_obs_shares_false_public_obs xms); exact Hshare_false.
split; first by rewrite (L_ms3c_obs_global_public_obs xms); exact Hglob.
split; first by rewrite (L_ms3c_obs_programmed_public_obs xms); exact Hprog.
split; first exact Hquery.
split; first by rewrite (L_ms3c_obs_true_ann_public_obs xms); exact Hann_true.
by rewrite (L_ms3c_obs_anns_false_public_obs xms); exact Hann_false.
qed.

lemma L_ms3c_public_obs_payload_alignment (xms : ms_public_input) :
  let obs = ms_game_view_public_obs xms in
  (ms3c_phase1_payload_from_public_input xms).`mscp_programmed_challenge =
    ms3c_obs_programmed_challenge obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_global_challenge =
    ms_comparison_global_challenge obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_share_true =
    ms3c_obs_share_true obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_ann_true =
    ms3c_obs_ann_true obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_share_false =
    ms3c_obs_shares_false obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_ann_false =
    ms3c_obs_anns_false obs.
proof.
rewrite /=.
have [_ [Hann_true Hshare_true]] := L_ms3c_phase1_payload_uses_ms3b_carrier xms.
have [Hann_false [Hshare_false [Hprog Hglob]]] :=
  L_ms3c_phase1_payload_uses_concrete_public_surface xms.
have Hann_true_pub := Hann_true.
rewrite /ms3c_phase1_comparison_carrier_from_public_input
  /ms3b_phase1_comparison_carrier /ms3b_phase1_comparison_true_opening
  /ms3b_phase1_comparison_true_share /= in Hann_true_pub.
have Hshare_true_pub := Hshare_true.
rewrite /ms3c_phase1_comparison_carrier_from_public_input
  /ms3b_phase1_comparison_carrier /ms3b_phase1_comparison_true_opening
  /ms3b_phase1_comparison_true_share /= in Hshare_true_pub.
split; first by rewrite (L_ms3c_obs_programmed_public_obs xms); exact Hprog.
split; first by rewrite (L_ms3c_obs_global_public_obs xms); exact Hglob.
split; first by rewrite (L_ms3c_obs_true_share_public_obs xms); exact Hshare_true_pub.
split; first by rewrite (L_ms3c_obs_true_ann_public_obs xms); exact Hann_true_pub.
split; first by rewrite (L_ms3c_obs_shares_false_public_obs xms); exact Hshare_false.
by rewrite (L_ms3c_obs_anns_false_public_obs xms); exact Hann_false.
qed.

op ms3c_game_pr_stage (xms : ms_public_input) (s : seed) (st : ms_game_stage) : ms_game_stage =
  if ms3c_comparison_game_pr_equiv xms s /\
     (st = MSGameStageAfterComparison \/ st = MSGameStageSim)
  then MSGameStageAfterComparison
  else st.

op ms3b_game_pr_stage (xms : ms_public_input) (st : ms_game_stage) : ms_game_stage =
  if ms3b_true_clause_game_pr_equiv xms /\
     (st = MSGameStageAfterBitness \/ st = MSGameStageAfterComparison)
  then MSGameStageAfterBitness
  else st.

op ms3a_game_pr_stage (xms : ms_public_input) (s : seed) (st : ms_game_stage) : ms_game_stage =
  if ms3a_bitness_real_sim_equiv xms s /\
     (st = MSGameStageAfterRom \/ st = MSGameStageAfterBitness)
  then MSGameStageAfterRom
  else st.

op game_pr_ms_core
  (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (obs : ms_v2_transcript_observable) (st : ms_game_stage)
  (lep : le_transcript_observable option)
  (D : distinguisher) : real =
  ms_view_distinguish_pr (d_ms_game_stage_observable_v2 x s xms st) D.

(* Concrete lower probability interface for MS views. The stored `obs` / `lep`
  fields remain part of `game_view`, but the MS probability projection is now
  computed from the stage-indexed lower distribution surface. MS1 and MS2 are
  both proved on that surface below. *)

(* Lower MS1/MS2 bridge surface: all public fields remain fixed and only the
   abstract MS stage changes inside `game_pr_ms_core`. *)
lemma A_MS1_hash_binding_game_pr_core_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    game_pr_ms_core x s xms obs MSGameStageReal lep D -
    game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D <=
    epsilon_ms_hash_binding.
proof.
move=> x s xms obs lep D Hnonneg.
rewrite /game_pr_ms_core.
exact (A_MS1_hash_binding_bad_event_bound x s xms D).
qed.

lemma A_MS2_rom_programming_game_pr_core_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D -
    game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <=
    epsilon_ms_rom_programmability.
proof.
move=> x s xms obs lep D Hnonneg.
rewrite /game_pr_ms_core.
exact (A_MS2_rom_programming_transition_bound x s xms D).
qed.

op game_pr_g2_core
  (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_sim_view x s) D.

op game_pr_g1_le_core
  (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_real_view x s) D.

op game_pr (v : game_view) (D : distinguisher) : real =
  with v = GV_ms r =>
    game_pr_ms_core r.`msgv_qssm_pub r.`msgv_seed r.`msgv_ms_pub r.`msgv_ms_obs
      (ms3a_game_pr_stage r.`msgv_ms_pub r.`msgv_seed
        (ms3b_game_pr_stage r.`msgv_ms_pub
          (ms3c_game_pr_stage r.`msgv_ms_pub r.`msgv_seed r.`msgv_stage)))
      r.`msgv_le_placeholder D
  with v = GV_g1_le_real r =>
    game_pr_g1_le_core r.`qg1_pub r.`qg1_seed D
  with v = GV_g2_full_sim r =>
    game_pr_g2_core r.`qg2_pub r.`qg2_seed D.

op Adv (v1 v2 : game_view) (D : distinguisher) : real =
  game_pr v1 D - game_pr v2 D.

lemma Adv_def :
  forall (v1 v2 : game_view) (D : distinguisher),
    Adv v1 v2 D = game_pr v1 D - game_pr v2 D.
proof. by []. qed.

op Adv_G0_G1_MS (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G_MS_real x xms s) (G_MS_sim x xms s) D.

op Adv_G1_MS_to_LE (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G_MS_sim x xms s) (G1_le_real_projection x xms s) D.

op Adv_G1_G2_LE (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G1_le_real_projection x xms s) (G2_full_sim x s) D.

op Adv_G0_G2_QSSM (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G0_real_qssm x xms s) (G2_full_sim x s) D.

lemma A_game_pr_on_G_MS_sim_equals_ms_real_projection :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G_MS_sim x xms s) D =
    ms_view_distinguish_pr (d_ms3a_bitness_real_observable_v2 xms) D.
proof.
move=> x xms s D.
have H3c : ms3c_comparison_game_pr_equiv xms s.
- move=> Hann Ha2 Hfalse Htrue Hsum.
  exact (MS_3c_exact_comparison_simulation xms s Hann Ha2 Hfalse Htrue Hsum).
have H3b : ms3b_true_clause_game_pr_equiv xms.
- move=> vb tb p clause_pub r Hop Hhd Htcp Hob.
  exact (MS_3b_true_clause_characterization xms vb tb p clause_pub r Hop Hhd Htcp Hob).
have H3a : ms3a_bitness_real_sim_equiv xms s.
- exact (MS_3a_exact_bitness_simulation xms s).
rewrite /game_pr /G_MS_sim /G1_ms_sim_le_real /mk_ms_game_view /=.
have Hst3c :
    ms3c_game_pr_stage xms s MSGameStageSim = MSGameStageAfterComparison.
- rewrite /ms3c_game_pr_stage H3c /=.
  by [].
have Hst3b :
    ms3b_game_pr_stage xms MSGameStageAfterComparison = MSGameStageAfterBitness.
- rewrite /ms3b_game_pr_stage H3b /=.
  by [].
have Hst3a :
    ms3a_game_pr_stage xms s MSGameStageAfterBitness = MSGameStageAfterRom.
- rewrite /ms3a_game_pr_stage H3a /=.
  by [].
rewrite Hst3c Hst3b Hst3a /game_pr_ms_core /d_ms_game_stage_observable_v2 /=.
rewrite -(L_ms2_rom_programming_transition_zero x s xms D).
rewrite -(L_ms1_hash_binding_stage_zero x s xms D).
by rewrite /d_ms_game_stage_observable_v2 /=.
qed.

lemma A_G1_MS_to_LE_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    Adv_G1_MS_to_LE x (extract_ms_public x) s D <= 0%r.
proof.
move=> x s D.
rewrite /Adv_G1_MS_to_LE Adv_def.
rewrite (A_game_pr_on_G_MS_sim_equals_ms_real_projection x (extract_ms_public x) s D).
rewrite /game_pr /G1_le_real_projection /= /game_pr_g1_le_core.
rewrite (A_extract_ms_public_real_view_probability_eq x s D).
have -> :
  le_view_distinguish_pr (d_le_real_view x s) D -
  le_view_distinguish_pr (d_le_real_view x s) D = 0%r by ring.
by [].
qed.

(* Telescoping identity: end-to-end MS advantage equals sum of segment advs. *)
lemma A_adv_ms_hop_telescope (xq : qssm_public_input) (xms : ms_public_input) (sq : seed) (Dq : distinguisher) :
  Adv (G_MS_real xq xms sq) (G_MS_sim xq xms sq) Dq =
  Adv (G_MS_real xq xms sq) (G_MS_after_binding xq xms sq) Dq +
  Adv (G_MS_after_binding xq xms sq) (G_MS_after_rom xq xms sq) Dq +
  Adv (G_MS_after_rom xq xms sq) (G_MS_after_bitness xq xms sq) Dq +
  Adv (G_MS_after_bitness xq xms sq) (G_MS_after_comparison xq xms sq) Dq +
  Adv (G_MS_after_comparison xq xms sq) (G_MS_sim xq xms sq) Dq.
proof.
rewrite !(Adv_def _ _ Dq).
ring.
qed.

(* Standard game-hop arithmetic over advantage differences. *)
lemma A_adv_gamehop_triangle :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    Adv_G0_G2_QSSM x xms s D <=
      Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
proof.
move=> x xms s D.
rewrite /Adv_G0_G2_QSSM /Adv_G0_G1_MS /Adv_G1_MS_to_LE /Adv_G1_G2_LE.
rewrite !(Adv_def _ _ D).
have ->:
    game_pr (G0_real_qssm x xms s) D - game_pr (G2_full_sim x s) D =
    (game_pr (G_MS_real x xms s) D - game_pr (G_MS_sim x xms s) D) +
    (game_pr (G_MS_sim x xms s) D - game_pr (G1_le_real_projection x xms s) D) +
    (game_pr (G1_le_real_projection x xms s) D - game_pr (G2_full_sim x s) D).
  ring.
by [].
qed.
