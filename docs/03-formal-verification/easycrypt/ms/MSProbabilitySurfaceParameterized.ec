require import AllCore List Distr.
require import SDist.
require import StdOrder.
require import QssmTypes Algebra.
require import FS.
require import TranscriptObservable.
require import MS.
require import SourceTypes SourceModel.
require import MSProbabilitySurface.
require import SourceHashBindingSemanticBridgeParameterized.
require import ComparisonPayloadSemanticBridgeParameterized.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Parallel parameterized MS probability surface.
   This file leaves the existing demo semantic route untouched and lifts the
   theorem-facing public-endpoint surface onto the parameterized MS1/MS2 bridge
   companions. The staged public-endpoint route stays above this layer. *)

lemma A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
have Hdemo :=
  A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound x s xms D.
rewrite /MS.epsilon_ms_hash_binding_semantic in Hdemo.
rewrite -epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized.
exact Hdemo.
qed.

lemma A_MS2_rom_programming_parameterized_public_endpoint_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hdemo :=
  A_MS2_rom_programming_semantic_public_endpoint_transition_bound x s xms D.
rewrite -epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized.
exact Hdemo.
qed.

lemma A_MS_public_endpoint_parameterized_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
     ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hdemo :=
  A_MS1_to_MS2_semantic_public_endpoint_transition_bound x s xms D.
rewrite /MS.epsilon_ms_hash_binding_semantic in Hdemo.
rewrite -epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized.
rewrite -epsilon_ms_rom_programmability_semantic_eq_epsilon_ms_rom_programmability_parameterized.
exact Hdemo.
qed.