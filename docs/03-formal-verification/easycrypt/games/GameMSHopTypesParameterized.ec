require import AllCore.
require import QssmTypes.
require import SourceTypes.
require import MSProbabilitySurface.
require import SourceHashBindingSemanticBridgeParameterized.
require import GameAdvantage.
require import GameViews.
require import GameAdvantageParameterized.
require import GameMSHopTypes.
require ParameterizedBudgetParameters.

(* Parallel parameterized staged MS wrapper surface.
   This file re-exposes the staged public-endpoint route above
   `GameAdvantageParameterized.ec` without touching the canonical live G0->G1
   theorem path. *)

lemma A_MS1_hash_binding_parameterized_stage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterBinding D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
move=> x s xms D.
exact (A_MS1_hash_binding_parameterized_game_advantage_bound x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_stage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterRom D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
exact (A_MS2_rom_programming_parameterized_game_advantage_bound x s xms D).
qed.

lemma A_MS_public_endpoint_parameterized_stage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
exact (A_MS_public_endpoint_parameterized_game_advantage_bound x s xms D).
qed.

lemma A_MS1_canonical_hash_binding_parameterized_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
move=> x xms s D.
have Hsem : 0%r <= MS.epsilon_ms_hash_binding_semantic.
  rewrite /MS.epsilon_ms_hash_binding_semantic.
  rewrite epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized.
  exact ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized_nonneg.
have Hdemo := A_MS1_canonical_hash_binding_semantic_bound x xms s D Hsem.
rewrite /MS.epsilon_ms_hash_binding_semantic in Hdemo.
rewrite epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized in Hdemo.
exact Hdemo.
qed.

lemma A_MS2_canonical_rom_programming_parameterized_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x xms s D.
rewrite /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
exact (A_MS2_rom_programming_parameterized_canonical_game_pr_core_bound
  x s xms (ms_game_view_public_obs xms) None D).
qed.