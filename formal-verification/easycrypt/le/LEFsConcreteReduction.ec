require import AllCore Distr SDist Real Ring.
require import StdOrder.
require import QssmTypes FS.

(*---*) import RealOrder.

require import LEFsProgrammingParameterizedView.

(* Parallel reduction-facing LE FS surface.
   This introduces an external reduction quantity for the concrete route
   without altering the frozen toy FS bad-branch equalities. *)

op le_fs_concrete_reduction_advantage
  (x : qssm_public_input) (s : seed) : real.

pred le_fs_concrete_reduction_obligation
  (epsilon_le_fs_bound : real) (x : qssm_public_input) (s : seed) =
  sdist (d_le_parameterized_post_fs_semantic_programmed_view x s)
    (d_le_parameterized_fs_shadow_semantic_post_marginal x s) <=
      le_fs_concrete_reduction_advantage x s /\
  le_fs_concrete_reduction_advantage x s <= epsilon_le_fs_bound.

lemma A_LE_fs_concrete_reduction_bound_from_obligation
  (epsilon_le_fs_bound : real) (x : qssm_public_input) (s : seed) :
  le_fs_concrete_reduction_obligation epsilon_le_fs_bound x s =>
  sdist (d_le_parameterized_post_fs_semantic_programmed_view x s)
    (d_le_parameterized_fs_shadow_semantic_post_marginal x s) <=
      epsilon_le_fs_bound.
proof.
move=> Hobl.
case: Hobl => Hsdist Hbound.
by apply (ler_trans _ _ _ Hsdist Hbound).
qed.