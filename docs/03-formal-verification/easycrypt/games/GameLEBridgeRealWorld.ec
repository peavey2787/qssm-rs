require import QssmTypes.
require import SourceTypes.
require import Real.
require import LESurface.
require import LESetB.
require import LERejection.
require import LEFsProgramming.
require import LEViewIndist.
require import LEStatisticalDistance.
require import LEStatisticalDistanceRealWorld.
require import LERejectionSamplerMassLiveParameterized.
require import LEFsProgrammingLiveParameterizedMass.
require import GameAdvantage.
require import GameLEBridge.
require import RealWorldBudgetParameters RealWorldBudgetObligations.

lemma A_LE_HVZK_semantic_realworld_budget_transition_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_realworld_obligations b
      (le_rejection_parameterized_failure_probability x s)
      LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass =>
    le_semantic_view_advantage_bound_from_realworld_budget b x s D.
proof.
move=> x s D Hsetb Heps Hleeqv Hrw.
have Hsetb' := A_LE_SetB_params_sound x s D Hsetb.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Heps.
have Hfs' := A_LE_fs_programming_bound x s D Hleeqv.
have Hrealdef : le_real_view_distribution_defined x s.
  exact (A_LE_real_view_distribution_defined x s D Hsetb').
have Hsimdef : le_sim_view_distribution_defined x s.
  exact (A_LE_sim_view_distribution_defined x s D Hsetb').
have Hind : le_real_sim_view_indistinguishable x s D.
  exact (A_LE_real_sim_view_indistinguishable x s D Hrealdef Hsimdef Hrej' Hfs').
exact (A_LE_semantic_view_advantage_bound_from_realworld_budget b x s D
  Hrealdef Hsimdef Hind Hrw).
qed.

lemma A_G1_to_G2_le_semantic_realworld_budget_transition_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_realworld_obligations b
      (le_rejection_parameterized_failure_probability x s)
      LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass =>
    Adv_G1_G2_LE x xms s D <= epsilon_le_realworld b.
proof.
move=> x xms s D Hsetb Heps Hleeqv Hrw.
have Hhvzk :=
  A_LE_HVZK_semantic_realworld_budget_transition_bound b x s D
    Hsetb Heps Hleeqv Hrw.
rewrite /le_semantic_view_advantage_bound_from_realworld_budget in Hhvzk.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hhvzk.
qed.