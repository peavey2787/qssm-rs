require import AllCore.
require import QssmTypes.
require import SourceTypes.
require import MSProbabilitySurface.
require import GameAdvantage.
require import GameAdvantageParameterized.
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