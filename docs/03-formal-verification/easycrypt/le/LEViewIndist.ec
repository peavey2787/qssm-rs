require import QssmTypes.
require import AllCore Distr.
require import LESurface.
require import LESetB.
require import LERejection.
require import LEFsProgramming.

pred le_real_sim_view_indistinguishable (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_rejection_sampling_hiding_bound x s D /\
  le_fs_programming_hiding_bound x s D.

lemma L_LE_combined_hiding_implies_view_indist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D Hrej Hfs.
rewrite /le_real_sim_view_indistinguishable.
by split.
qed.

lemma A_LE_real_sim_view_indistinguishable_from_bound_ok :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D Hrej Hfs.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Hrej.
have Hfs' := A_LE_fs_programming_bound x s D Hfs.
exact (L_LE_combined_hiding_implies_view_indist x s D Hrej' Hfs').
qed.

lemma A_LE_real_sim_view_indistinguishable :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D _ _ Hrej Hfs.
exact (L_LE_combined_hiding_implies_view_indist x s D Hrej Hfs).
qed.

lemma A_LE_real_to_post_rejection_distribution_link :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    d_le_post_rejection_view x s = dmap (d_le_real_view x s) le_post_rejection_surrogate.
proof.
move=> x s Hr.
by rewrite /d_le_post_rejection_view.
qed.

lemma A_LE_post_rejection_to_sim_distribution_link :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    d_le_sim_view x s = dmap (d_le_post_rejection_view x s) le_fs_view_surrogate.
proof.
move=> x s D _ _ _ _.
by rewrite /d_le_sim_view.
qed.
