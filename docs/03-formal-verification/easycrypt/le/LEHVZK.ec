require import QssmTypes.
require import Real.
require import LESurface.
require import LESetB.
require import LERejection.
require import LEFsProgramming.
require import LEViewIndist.
require import LEStatisticalDistance.

lemma A_LE_real_sim_transcript_equiv_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_hvzk_bound x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hrealdef : le_real_view_distribution_defined x s.
  exact (A_LE_real_view_distribution_defined x s D Hsetb).
have Hsimdef : le_sim_view_distribution_defined x s.
  exact (A_LE_sim_view_distribution_defined x s D Hsetb).
have Hind : le_real_sim_view_indistinguishable x s D.
  exact (A_LE_real_sim_view_indistinguishable x s D Hrealdef Hsimdef Hrej Hfs).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hadv : le_view_advantage_bound_from_indistinguishability x s D.
  exact (A_LE_view_advantage_bound_from_indistinguishability x s D Hrealdef Hsimdef Hind Heps).
by rewrite /le_view_advantage_bound_from_indistinguishability in Hadv.
qed.

lemma A_LE_real_sim_transcript_semantic_equiv_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_semantic_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hrealdef : le_real_view_distribution_defined x s.
  exact (A_LE_real_view_distribution_defined x s D Hsetb).
have Hsimdef : le_sim_view_distribution_defined x s.
  exact (A_LE_sim_view_distribution_defined x s D Hsetb).
have Hind : le_real_sim_view_indistinguishable x s D.
  exact (A_LE_real_sim_view_indistinguishable x s D Hrealdef Hsimdef Hrej Hfs).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
exact (A_LE_semantic_view_advantage_bound_from_indistinguishability x s D Hrealdef Hsimdef Hind Heps).
qed.

lemma A_LE_SetB_HVZK_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_hvzk_bound x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hsetb' := A_LE_SetB_params_sound x s D Hsetb.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Hrej.
have Hfs' := A_LE_fs_programming_bound x s D Hfs.
exact (A_LE_real_sim_transcript_equiv_bound x s D Hsetb' Hrej' Hfs').
qed.

lemma A_LE_SetB_HVZK_semantic_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_semantic_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hsetb' := A_LE_SetB_params_sound x s D Hsetb.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Hrej.
have Hfs' := A_LE_fs_programming_bound x s D Hfs.
exact (A_LE_real_sim_transcript_semantic_equiv_bound x s D Hsetb' Hrej' Hfs').
qed.

lemma A_LE_HVZK_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_hvzk_transition_bound x s D.
proof.
move=> x s D Hsetb Heps Hfs.
rewrite /le_hvzk_transition_bound.
exact (A_LE_SetB_HVZK_bound x s D Hsetb Heps Hfs).
qed.

lemma A_LE_HVZK_semantic_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_semantic_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hsetb Heps Hfs.
exact (A_LE_SetB_HVZK_semantic_bound x s D Hsetb Heps Hfs).
qed.
