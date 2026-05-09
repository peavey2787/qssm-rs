require import AllCore.
require import QssmTypes.
require import SourceTypes.
require import GameTypes.
require import MSProbabilitySurface.
require import MSProbabilitySurfaceParameterized.
require import GameAdvantage.
require ParameterizedBudgetParameters.

(* Parallel parameterized game-advantage wrappers.
   This file keeps the existing demo route untouched and lifts the parallel
   public-endpoint surface from `MSProbabilitySurfaceParameterized.ec` onto the
   game-layer public-endpoint core in `GameAdvantage.ec`. The staged public-endpoint
   caveat remains above this layer. *)

lemma A_MS1_hash_binding_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterBinding D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
move=> x s xms D.
rewrite /game_pr_ms_public_endpoint_core.
rewrite /d_ms_public_endpoint_stage_observable_v2 /=.
exact (A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterRom D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
rewrite /game_pr_ms_public_endpoint_core.
rewrite /d_ms_public_endpoint_stage_observable_v2 /=.
exact (A_MS2_rom_programming_parameterized_public_endpoint_transition_bound x s xms D).
qed.

lemma A_MS_public_endpoint_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
rewrite /Adv_ms_public_endpoint /game_pr_ms_public_endpoint_core.
rewrite /d_ms_public_endpoint_stage_observable_v2 /=.
exact (A_MS_public_endpoint_parameterized_transition_bound x s xms D).
qed.