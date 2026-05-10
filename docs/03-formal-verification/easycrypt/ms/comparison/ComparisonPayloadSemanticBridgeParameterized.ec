require import AllCore.
require import QssmTypes.
require import SourceTypes.
require import ParameterizedBudgetParameters.
require import ComparisonPayloadSemanticLiveParameterizedMass.

(* Parallel parameterized MS2 semantic bridge.
   This keeps the demo semantic bridge untouched and exposes the live
   parameterized execution-owned bound under the existing theorem-facing name. *)

lemma A_MS2_rom_programming_execution_owned_parameterized_bound
  (x : ms_public_input) :
  ms_rom_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
exact (A_MS2_rom_programming_execution_owned_live_parameterized_bound x).
qed.