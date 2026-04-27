require import Real.
require import QssmTypes QssmSim.

theory QssmGames.

(* Game skeletons *)
op G0 : qssm_public_input -> seed -> game_view.
op G1 : qssm_public_input -> seed -> game_view.
op G2 : qssm_public_input -> seed -> game_view.

op Pr : game_view -> distinguisher -> real.
op Adv : game_view -> game_view -> distinguisher -> real.

axiom Adv_def :
  forall (v1 v2 : game_view) (D : distinguisher),
    Adv v1 v2 D = Pr v1 D - Pr v2 D.

(* Skeleton transition placeholders *)
axiom G0_to_G1_skeleton :
  forall (x : qssm_public_input) (s : seed), True.

axiom G1_to_G2_skeleton :
  forall (x : qssm_public_input) (s : seed), True.

end.
