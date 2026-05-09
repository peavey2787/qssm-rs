require import AllCore.
require import QssmTypes.
require import SourceTypes.
require import MSProbabilitySurface.
require import GameAdvantage.
require import GameMSHopTypesParameterized.
require ParameterizedBudgetParameters.

(* Parallel parameterized staged MS composition surface.
   This file re-exposes only the staged public-endpoint route and does not
   claim any canonical G0->G1 parameterized theorem. *)

lemma A_MS1_hash_binding_parameterized_staged_composition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterBinding D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
move=> x s xms D.
exact (A_MS1_hash_binding_parameterized_stage_bound x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_staged_composition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    game_pr_ms_public_endpoint_core x s xms MSPublicEndpointAfterRom D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
exact (A_MS2_rom_programming_parameterized_stage_bound x s xms D).
qed.

lemma A_MS_public_endpoint_parameterized_staged_composition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x xms s D.
exact (A_MS_public_endpoint_parameterized_stage_bound x s xms D).
qed.