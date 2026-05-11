require import AllCore Distr SDist Real Ring.
require import StdOrder.
require import QssmTypes FS.

(*---*) import RealOrder.

require import LESurface.
require import LERejectionSampler.
require import LEFsProgrammingSurface.
require import LERejection.
require import LERejectionSamplerParameterizedCore.
require import LEFsProgramming.
require import LEViewIndist.
require import LEStatisticalDistance.
require import LERejectionParameterized.
require import LEFsProgrammingParameterized.
require import LEFsProgrammingParameterizedView.
require import LEFsProgrammingFailureProbabilityParameterized.
require ParameterizedBudgetParameters.

pred le_semantic_view_advantage_bound_from_parameterized_budget
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_semantic_view_distinguishing_adv x s D <=
    ParameterizedBudgetParameters.epsilon_le_parameterized.

lemma A_LE_rejection_semantic_contributes_to_sdist_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s)
      (d_le_parameterized_post_rejection_view x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s D Hr _ Hrej _.
have Hdef : le_rejection_distribution_defined x s.
  exact (A_LE_rejection_distribution_defined x s Hrej).
have Hacc : le_rejection_acceptance_probability_bounded x s.
  exact (A_LE_rejection_acceptance_probability_bounded x s Hdef).
have Hshape : le_rejection_output_shape_preserved x s.
  exact (A_LE_rejection_output_shape_preserved x s Hacc).
exact (A_LE_rejection_sampler_semantic_sdist_parameterized_bound x s Hr Hdef Hacc Hshape).
qed.

lemma A_LE_fs_semantic_contributes_to_sdist_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_parameterized_post_fs_semantic_programmed_view x s)
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s D Hr Hs Hfs _.
exact (A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget_from_parameterized_midpoint
  x s D Hr Hs Hfs).
qed.

lemma A_LE_semantic_combined_hiding_bounds_sdist_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s)
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_parameterized.
proof.
move=> x s D Hr Hs Hrej Hfs Heps.
pose dr := d_le_real_view x s.
pose dmid := d_le_parameterized_post_rejection_view x s.
pose dprog := d_le_parameterized_post_fs_semantic_programmed_view x s.
pose dsem := d_le_parameterized_fs_shadow_semantic_post_marginal x s.
have Hrej' : sdist dr dmid <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
  exact (A_LE_rejection_semantic_contributes_to_sdist_parameterized_budget x s D Hr Hs Hrej Heps).
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
have Hfssem : sdist dprog dsem <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
  exact (A_LE_fs_semantic_contributes_to_sdist_parameterized_budget x s D Hr Hs Hfs Heps).
have Htri1 : sdist dr dsem <= sdist dr dmid + sdist dmid dsem.
  exact (sdist_triangle dmid dr dsem).
have Htri2 : sdist dmid dsem <= sdist dmid dprog + sdist dprog dsem.
  exact (sdist_triangle dprog dmid dsem).
have Hmid : sdist dmid dsem <=
    0%r + ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
  apply (ler_trans _ _ _ Htri2).
  exact (ler_add _ _ _ _ Hfs0 Hfssem).
have Hstep : sdist dr dsem <=
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized +
    (0%r + ParameterizedBudgetParameters.epsilon_le_fs_parameterized).
  apply (ler_trans _ _ _ Htri1).
  exact (ler_add _ _ _ _ Hrej' Hmid).
have Heq :
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized +
    (0%r + ParameterizedBudgetParameters.epsilon_le_fs_parameterized) =
    ParameterizedBudgetParameters.epsilon_le_parameterized.
  rewrite /ParameterizedBudgetParameters.epsilon_le_parameterized.
  by ring.
rewrite -Heq.
exact Hstep.
qed.

lemma A_LE_semantic_view_advantage_bound_from_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_semantic_view_advantage_bound_from_parameterized_budget x s D.
proof.
move=> x s D Hr Hs Hind Heps.
rewrite /le_semantic_view_advantage_bound_from_parameterized_budget.
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
case: Hind => Hrej Hfs.
have Hstat :
    sdist (d_le_real_view x s)
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_parameterized.
  exact (A_LE_semantic_combined_hiding_bounds_sdist_parameterized_budget x s D Hr Hs Hrej Hfs Heps).
pose dr := d_le_real_view x s.
pose ds := d_le_parameterized_fs_shadow_semantic_post_marginal x s.
pose E := le_distinguisher_event D.
have Habs : `|mu dr E - mu ds E| <= sdist dr ds.
  exact (sdist_upper_bound dr ds E).
have Hle : mu dr E - mu ds E <= `|mu dr E - mu ds E|.
  exact (ler_norm (mu dr E - mu ds E)).
apply (ler_trans _ _ _ Hle).
apply (ler_trans _ _ _ Habs Hstat).
qed.