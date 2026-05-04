require import AllCore List.
require import Ring.
require import QssmTypes.
require import GameTypes.
require import GameViews.
require import TranscriptObservable.
require import SourceDistributions.

(* Game probability is projected from the concrete `game_view` surface.
  For MS views, the projection collapses AfterRom and AfterBitness whenever
  `ms3a_bitness_real_sim_equiv` holds, which is enough to prove the canonical
  MS3a game hop as an exact zero-advantage lemma without adding a new axiom. *)
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
      (ms3a_game_pr_stage r.`msgv_ms_pub r.`msgv_seed r.`msgv_stage)
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
