require import AllCore List.
require import Ring.
require import Algebra.
require import QssmTypes.
require import GameTypes.
require import GameViews.
require import TranscriptObservable.
require import SourceModel.
require import SourceDistributions.
require import TrueClause ComparisonTypes ComparisonDigests ComparisonPayloadFromSeed.

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
rewrite /ms_game_view_public_obs /ms3a_public_v2_observable /ms3a_pack_observable.
rewrite /ms3c_phase1_payload_from_public_input /ms3c_phase1_comparison_carrier_from_public_input.
rewrite /ms3b_phase1_comparison_carrier /ms3b_phase1_comparison_true_share.
rewrite /ms3c_public_false_announcements /ms3c_public_false_shares.
rewrite /ms3c_obs_programmed_challenge /ms3c_obs_share_true /ms3c_obs_ann_true.
rewrite /ms3c_obs_shares_false /ms3c_obs_anns_false /ms_comparison_global_challenge /=.
have Hix : ms3c_public_false_clause_indices xms = [0] by trivial.
rewrite Hix /=.
  split; first by [].
  split; first by [].
  split; first by [].
  split; first by [].
  split; first by [].
  by [].
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

op game_pr_ms_core : qssm_public_input -> seed -> ms_public_input ->
  ms_v2_transcript_observable -> ms_game_stage -> le_transcript_observable option ->
  distinguisher -> real.

op game_pr_g2_core : qssm_public_input -> seed -> distinguisher -> real.

op game_pr (v : game_view) (D : distinguisher) : real =
  with v = GV_ms r =>
    game_pr_ms_core r.`msgv_qssm_pub r.`msgv_seed r.`msgv_ms_pub r.`msgv_ms_obs
      (ms3a_game_pr_stage r.`msgv_ms_pub r.`msgv_seed
        (ms3b_game_pr_stage r.`msgv_ms_pub
          (ms3c_game_pr_stage r.`msgv_ms_pub r.`msgv_seed r.`msgv_stage)))
      r.`msgv_le_placeholder D
  with v = GV_g2_full_sim r =>
    game_pr_g2_core r.`qg2_pub r.`qg2_seed D.

op Adv (v1 v2 : game_view) (D : distinguisher) : real =
  game_pr v1 D - game_pr v2 D.

lemma Adv_def :
  forall (v1 v2 : game_view) (D : distinguisher),
    Adv v1 v2 D = game_pr v1 D - game_pr v2 D.
proof. by []. qed.

op Adv_G0_G1_MS (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G0_real_qssm x xms s) (G1_ms_sim_le_real x xms s) D.

op Adv_G1_G2_LE (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G1_ms_sim_le_real x xms s) (G2_full_sim x s) D.

op Adv_G0_G2_QSSM (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G0_real_qssm x xms s) (G2_full_sim x s) D.

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
    Adv_G0_G2_QSSM x xms s D <= Adv_G0_G1_MS x xms s D + Adv_G1_G2_LE x xms s D.
proof.
move=> x xms s D.
rewrite /Adv_G0_G2_QSSM /Adv_G0_G1_MS /Adv_G1_G2_LE.
rewrite !(Adv_def _ _ D).
have ->:
    game_pr (G0_real_qssm x xms s) D - game_pr (G2_full_sim x s) D =
    (game_pr (G0_real_qssm x xms s) D - game_pr (G1_ms_sim_le_real x xms s) D) +
    (game_pr (G1_ms_sim_le_real x xms s) D - game_pr (G2_full_sim x s) D).
  ring.
by [].
qed.
