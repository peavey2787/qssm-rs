require import AllCore Distr SDist Real Ring.
require import StdOrder.
require import QssmTypes SourceTypes FS.

(*---*) import RealOrder.

require import LESurface.
require import LEStatisticalDistance.
require import LERejectionSamplerParameterizedCore.
require import LEFsProgrammingSurface.
require import LEFsProgrammingParameterizedView.
require import GameAdvantage.
require import GameLEBridge.
require import LERejectionConcreteReduction.
require import LEFsConcreteReduction.

(* Combined reduction-facing LE surface.
   This composes external concrete rejection and FS reductions without
   asserting that the frozen toy lower actuals are negligible. *)

lemma A_LE_semantic_view_advantage_bound_from_reduction_obligations :
  forall (epsilon_le_rej_bound epsilon_le_fs_bound : real)
         (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_concrete_reduction_obligation epsilon_le_rej_bound x s =>
    le_fs_concrete_reduction_obligation epsilon_le_fs_bound x s =>
    le_semantic_view_distinguishing_adv x s D <=
      epsilon_le_rej_bound + epsilon_le_fs_bound.
proof.
move=> epsilon_le_rej_bound epsilon_le_fs_bound x s D Hrejobl Hfsobl.
pose dr := d_le_real_view x s.
pose dmid := d_le_parameterized_post_rejection_view x s.
pose dprog := d_le_parameterized_post_fs_semantic_programmed_view x s.
pose dsem := d_le_parameterized_fs_shadow_semantic_post_marginal x s.
have Hrej : sdist dr dmid <= epsilon_le_rej_bound.
  exact (A_LE_rejection_concrete_reduction_bound_from_obligation
    epsilon_le_rej_bound x s Hrejobl).
have Hfs0 : sdist dmid dprog <= 0%r.
  rewrite /dmid /dprog /d_le_parameterized_post_fs_semantic_programmed_view.
  have Hmap :
      dmap (d_le_parameterized_post_rejection_view x s) le_fs_view_surrogate =
      dmap (d_le_parameterized_post_rejection_view x s)
        (fun (obs : le_transcript_observable) => obs).
    apply eq_dmap_in=> obs _ /=.
    exact (LEFsProgrammingSurface.le_fs_surrogate_transform_id obs).
  rewrite Hmap dmap_id sdistdd.
  by [].
have Hfssem : sdist dprog dsem <= epsilon_le_fs_bound.
  exact (A_LE_fs_concrete_reduction_bound_from_obligation
    epsilon_le_fs_bound x s Hfsobl).
have Htri1 : sdist dr dsem <= sdist dr dmid + sdist dmid dsem.
  exact (sdist_triangle dmid dr dsem).
have Htri2 : sdist dmid dsem <= sdist dmid dprog + sdist dprog dsem.
  exact (sdist_triangle dprog dmid dsem).
have Hmid : sdist dmid dsem <= 0%r + epsilon_le_fs_bound.
  apply (ler_trans _ _ _ Htri2).
  exact (ler_add _ _ _ _ Hfs0 Hfssem).
have Hstep : sdist dr dsem <= epsilon_le_rej_bound + (0%r + epsilon_le_fs_bound).
  apply (ler_trans _ _ _ Htri1).
  exact (ler_add _ _ _ _ Hrej Hmid).
have Hstat : sdist dr dsem <= epsilon_le_rej_bound + epsilon_le_fs_bound.
  have -> : epsilon_le_rej_bound + (0%r + epsilon_le_fs_bound) =
      epsilon_le_rej_bound + epsilon_le_fs_bound by ring.
  exact Hstep.
have Hsim :
    le_view_distinguish_pr
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) D =
    le_view_distinguish_pr
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s) D.
  by rewrite (le_view_distinguish_pr_parameterized_fs_shadow_semantic_post_marginal_matches_demo
    x s D).
rewrite /le_semantic_view_distinguishing_adv.
rewrite Hsim.
rewrite /le_view_distinguish_pr.
pose E := le_distinguisher_event D.
have Habs : `|mu dr E - mu dsem E| <= sdist dr dsem.
  exact (sdist_upper_bound dr dsem E).
have Hle : mu dr E - mu dsem E <= `|mu dr E - mu dsem E|.
  exact (ler_norm (mu dr E - mu dsem E)).
apply (ler_trans _ _ _ Hle).
apply (ler_trans _ _ _ Habs Hstat).
qed.

lemma A_G1_to_G2_le_concrete_reduction_transition_bound_from_obligations :
  forall (epsilon_le_rej_bound epsilon_le_fs_bound : real)
         (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    le_rejection_concrete_reduction_obligation epsilon_le_rej_bound x s =>
    le_fs_concrete_reduction_obligation epsilon_le_fs_bound x s =>
    Adv_G1_G2_LE x xms s D <= epsilon_le_rej_bound + epsilon_le_fs_bound.
proof.
move=> epsilon_le_rej_bound epsilon_le_fs_bound x xms s D Hrejobl Hfsobl.
have Hle := A_LE_semantic_view_advantage_bound_from_reduction_obligations
  epsilon_le_rej_bound epsilon_le_fs_bound x s D Hrejobl Hfsobl.
rewrite /le_semantic_view_distinguishing_adv in Hle.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hle.
qed.