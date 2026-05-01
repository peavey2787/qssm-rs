require import AllCore Distr SDist Real Ring.
require import StdOrder.
require import QssmTypes FS.

(*---*) import RealOrder.

require import LESurface.
require import LERejection.
require import LEFsProgramming.
require import LEViewIndist.

pred le_view_advantage_bound_from_indistinguishability
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_hvzk_bound x s D.

lemma A_LE_rejection_contributes_to_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s) (d_le_post_rejection_view x s) <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hrej Heps.
rewrite (A_LE_real_to_post_rejection_distribution_link x s Hr).
exact (A_LE_rejection_half_sdist_bound x s D Hr Hs Hrej Heps).
qed.

lemma A_LE_fs_contributes_to_sdist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_post_rejection_view x s) (d_le_sim_view x s) <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hfs Heps.
rewrite /d_le_sim_view.
exact (A_LE_fs_half_sdist_bound x s D Hr Hs Hfs Heps).
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
have Hrej' : sdist dr dmid <= (1%r / 2%r) * epsilon_le.
  exact (A_LE_rejection_contributes_to_sdist x s D Hr Hs Hrej Heps).
have Hfs' : sdist dmid ds <= (1%r / 2%r) * epsilon_le.
  exact (A_LE_fs_contributes_to_sdist x s D Hr Hs Hfs Heps).
have Htri : sdist dr ds <= sdist dr dmid + sdist dmid ds.
  exact (sdist_triangle dmid dr ds).
apply (ler_trans (sdist dr dmid + sdist dmid ds)).
  exact Htri.
apply (ler_trans (((1%r / 2%r) * epsilon_le) + ((1%r / 2%r) * epsilon_le))).
  by apply ler_add.
have Heq :
  ((1%r / 2%r) * epsilon_le) + ((1%r / 2%r) * epsilon_le) = epsilon_le.
  rewrite -(RField.mulrDl (1%r / 2%r) (1%r / 2%r) epsilon_le).
  have ->: (1%r / 2%r) + (1%r / 2%r) = 1%r by exact (RField.double_half 1%r).
  by rewrite RField.mul1r.
rewrite Heq.
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
