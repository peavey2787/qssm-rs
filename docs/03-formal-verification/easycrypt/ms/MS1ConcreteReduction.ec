require import AllCore Real Ring StdOrder.

(*---*) import RealOrder.

require import QssmTypes.
require import SourceTypes.
require import GameViews.
require import GameAdvantage.

(* Parallel reduction-facing MS1 surface.
   This introduces an external reduction quantity for the concrete route
   without altering the frozen toy MS1 execution-owned equalities. *)

op ms1_concrete_reduction_advantage
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) : real.

pred ms1_concrete_reduction_obligation
  (epsilon_ms1_bound : real)
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) =
  Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <=
    ms1_concrete_reduction_advantage x s xms D /\
  ms1_concrete_reduction_advantage x s xms D <= epsilon_ms1_bound.

lemma A_MS1_concrete_reduction_bound_from_obligation
  (epsilon_ms1_bound : real)
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms1_concrete_reduction_obligation epsilon_ms1_bound x s xms D =>
  Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms1_bound.
proof.
move=> Hobl.
case: Hobl => Hadv Hbound.
by apply (ler_trans _ _ _ Hadv Hbound).
qed.