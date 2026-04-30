require import AllCore List.
require import QssmTypes.
require import GameViews.

op game_pr : game_view -> distinguisher -> real.
op Adv : game_view -> game_view -> distinguisher -> real.

axiom Adv_def :
  forall (v1 v2 : game_view) (D : distinguisher),
    Adv v1 v2 D = game_pr v1 D - game_pr v2 D.

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
smt(Adv_def).
qed.

(* Standard game-hop arithmetic over advantage differences. *)
lemma A_adv_gamehop_triangle :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    Adv_G0_G2_QSSM x xms s D <= Adv_G0_G1_MS x xms s D + Adv_G1_G2_LE x xms s D.
proof.
move=> x xms s D.
rewrite /Adv_G0_G2_QSSM /Adv_G0_G1_MS /Adv_G1_G2_LE.
rewrite !(Adv_def _ _ D).
smt().
qed.
