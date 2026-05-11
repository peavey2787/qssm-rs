require import QssmTypes.
require import SourceTypes.
require import Real.
require import LESurface.
require import LEStatisticalDistance.
require import LEHVZKParameterized.
require import GameAdvantage.
require import GameLEBridge.
require ParameterizedBudgetParameters.

lemma A_G1_to_G2_le_semantic_parameterized_budget_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D <= ParameterizedBudgetParameters.epsilon_le_parameterized.
proof.
move=> x xms s D Hsetb Heps Hleeqv.
have Hhvzk :=
  A_LE_HVZK_semantic_parameterized_budget_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_semantic_view_advantage_bound_from_parameterized_budget in Hhvzk.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hhvzk.
qed.