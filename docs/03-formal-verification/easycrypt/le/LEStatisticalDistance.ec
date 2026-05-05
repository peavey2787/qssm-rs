require import AllCore Distr SDist Real Ring.
require import StdOrder.
require import QssmTypes FS.

(*---*) import RealOrder.

require BudgetParameters.
require import LESurface.
require import LERejection.
require import LEFsProgramming.
require import LEViewIndist.

pred le_view_advantage_bound_from_indistinguishability
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_hvzk_bound x s D.

op le_semantic_view_distinguishing_adv
  (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_real_view x s) D -
  le_view_distinguish_pr
    (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) D.

pred le_semantic_view_advantage_bound_from_indistinguishability
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_semantic_view_distinguishing_adv x s D <=
    BudgetParameters.epsilon_le_rej +
    LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.

lemma A_LE_rejection_contributes_to_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
      <= BudgetParameters.epsilon_le_rej.
proof.
move=> x s D Hr _ Hrej _.
have Hdef : le_rejection_distribution_defined x s.
  exact (A_LE_rejection_distribution_defined x s Hrej).
have Hacc : le_rejection_acceptance_probability_bounded x s.
  exact (A_LE_rejection_acceptance_probability_bounded x s Hdef).
have Hshape : le_rejection_output_shape_preserved x s.
  exact (A_LE_rejection_output_shape_preserved x s Hacc).
exact (A_LE_rejection_sampler_sdist_bound x s Hr Hdef Hacc Hshape).
qed.

lemma A_LE_fs_contributes_to_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_post_rejection_view x s) (d_le_sim_view x s)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D Hr Hs Hfs _.
rewrite /d_le_sim_view.
exact (A_LE_fs_surrogate_sdist_bound x s D Hr Hs Hfs).
qed.

lemma A_LE_fs_semantic_contributes_to_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (dmap (d_le_post_rejection_view x s) le_fs_view_surrogate)
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
      <= LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s D Hr Hs Hfs _.
exact (A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass x s D Hr Hs Hfs).
qed.

lemma A_LE_semantic_combined_hiding_bounds_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s)
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
      <= BudgetParameters.epsilon_le_rej +
         LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s D Hr Hs Hrej Hfs Heps.
pose dr := d_le_real_view x s.
pose dmid := d_le_post_rejection_view x s.
pose dprog := dmap (d_le_post_rejection_view x s) le_fs_view_surrogate.
pose dsem := LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s.
have Hrej' : sdist dr dmid <= BudgetParameters.epsilon_le_rej.
  exact (A_LE_rejection_contributes_to_sdist x s D Hr Hs Hrej Heps).
have Hfs0 : sdist dmid dprog <= BudgetParameters.epsilon_le_fs.
  exact (A_LE_fs_contributes_to_sdist x s D Hr Hs Hfs Heps).
have Hfssem : sdist dprog dsem <= LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
  exact (A_LE_fs_semantic_contributes_to_sdist x s D Hr Hs Hfs Heps).
have Htri1 : sdist dr dsem <= sdist dr dmid + sdist dmid dsem.
  exact (sdist_triangle dmid dr dsem).
have Htri2 : sdist dmid dsem <= sdist dmid dprog + sdist dprog dsem.
  exact (sdist_triangle dprog dmid dsem).
have Hmid : sdist dmid dsem <=
    BudgetParameters.epsilon_le_fs + LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
  apply (ler_trans _ _ _ Htri2).
  exact (ler_add _ _ _ _ Hfs0 Hfssem).
have Hstep : sdist dr dsem <=
    BudgetParameters.epsilon_le_rej +
    (BudgetParameters.epsilon_le_fs + LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass).
  apply (ler_trans _ _ _ Htri1).
  exact (ler_add _ _ _ _ Hrej' Hmid).
rewrite /BudgetParameters.epsilon_le_fs in Hstep.
have -> : BudgetParameters.epsilon_le_rej +
    (0%r + LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass) =
  BudgetParameters.epsilon_le_rej + LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass by ring.
exact Hstep.
qed.

lemma A_LE_combined_hiding_bounds_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    le_view_statistical_distance_bound x s D.
proof.
move=> x s D Hr Hs Hrej Hfs Heps.
rewrite /le_view_statistical_distance_bound /le_view_statistical_distance.
pose dr := d_le_real_view x s.
pose dmid := d_le_post_rejection_view x s.
pose ds := d_le_sim_view x s.
have Hrej' : sdist dr dmid <= BudgetParameters.epsilon_le_rej.
  exact (A_LE_rejection_contributes_to_sdist x s D Hr Hs Hrej Heps).
have Hfs' : sdist dmid ds <= BudgetParameters.epsilon_le_fs.
  exact (A_LE_fs_contributes_to_sdist x s D Hr Hs Hfs Heps).
have Htri : sdist dr ds <= sdist dr dmid + sdist dmid ds.
  exact (sdist_triangle dmid dr ds).
apply (ler_trans (sdist dr dmid + sdist dmid ds)).
  exact Htri.
apply (ler_trans (BudgetParameters.epsilon_le_rej + BudgetParameters.epsilon_le_fs)).
  by apply ler_add.
rewrite /epsilon_le.
by apply lerr.
qed.

lemma A_LE_view_indist_to_sd_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_view_statistical_distance_bound x s D.
proof.
move=> x s D Hr Hs Hind Heps.
case: Hind => Hrej Hfs.
exact (A_LE_combined_hiding_bounds_sdist x s D Hr Hs Hrej Hfs Heps).
qed.

lemma A_LE_distinguisher_event_probability_bounded_by_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_distinguishing_adv x s D <= le_view_statistical_distance x s.
proof.
move=> x s D.
rewrite /le_view_distinguishing_adv /le_game_hop_adv
  /le_projected_real_adv_base /le_projected_sim_adv_base
  /le_view_statistical_distance.
pose dr := d_le_real_view x s.
pose ds := d_le_sim_view x s.
pose E := le_distinguisher_event D.
have Habs : `|mu dr E - mu ds E| <= sdist dr ds.
  exact (sdist_upper_bound dr ds E).
have Hle : mu dr E - mu ds E <= `|mu dr E - mu ds E|.
  apply ler_norm.
by apply (ler_trans _ _ _ Hle Habs).
qed.

lemma A_LE_sd_bound_to_adv_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_statistical_distance_bound x s D =>
    le_view_distinguishing_adv x s D <= le_view_statistical_distance x s.
proof.
move=> x s D _.
exact (A_LE_distinguisher_event_probability_bounded_by_sdist x s D).
qed.

lemma A_LE_projected_advantage_matches_view_distance :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_distinguishing_adv x s D = le_game_hop_adv x s D.
proof.
by move=> x s D; rewrite /le_view_distinguishing_adv.
qed.

lemma A_LE_view_advantage_bound_from_indistinguishability :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hr Hs Hind Heps.
rewrite /le_view_advantage_bound_from_indistinguishability /le_hvzk_bound.
have Hstat : le_view_statistical_distance_bound x s D.
  exact (A_LE_view_indist_to_sd_bound x s D Hr Hs Hind Heps).
have Hadv : le_view_distinguishing_adv x s D <= le_view_statistical_distance x s.
  exact (A_LE_sd_bound_to_adv_bound x s D Hstat).
have Hdist : le_view_statistical_distance x s <= epsilon_le.
  by rewrite /le_view_statistical_distance_bound in Hstat.
have Hadvhop : le_game_hop_adv x s D <= le_view_statistical_distance x s.
  rewrite -(A_LE_projected_advantage_matches_view_distance x s D).
  exact Hadv.
have Hfin : le_game_hop_adv x s D <= epsilon_le.
  by apply (ler_trans _ _ _ Hadvhop Hdist).
by exact Hfin.
qed.

lemma A_LE_semantic_view_advantage_bound_from_indistinguishability :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_semantic_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hr Hs Hind Heps.
case: Hind => Hrej Hfs.
rewrite /le_semantic_view_advantage_bound_from_indistinguishability.
rewrite /le_semantic_view_distinguishing_adv /le_view_distinguish_pr.
have Hstat :
  sdist (d_le_real_view x s)
    (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
    <= BudgetParameters.epsilon_le_rej +
       LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
  exact (A_LE_semantic_combined_hiding_bounds_sdist x s D Hr Hs Hrej Hfs Heps).
pose dr := d_le_real_view x s.
pose ds := LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s.
pose E := le_distinguisher_event D.
have Habs : `|mu dr E - mu ds E| <= sdist dr ds.
  exact (sdist_upper_bound dr ds E).
have Hle : mu dr E - mu ds E <= `|mu dr E - mu ds E|.
  exact (ler_norm (mu dr E - mu ds E)).
apply (ler_trans _ _ _ Hle).
apply (ler_trans _ _ _ Habs Hstat).
qed.
