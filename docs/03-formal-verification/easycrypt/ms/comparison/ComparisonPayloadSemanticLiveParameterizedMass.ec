require import AllCore Distr.
require import Real.
require import StdOrder.
require import QssmTypes.
require import SourceTypes.
require import ParameterizedBudgetParameters.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticSlotMassParameterized.
require import ComparisonPayloadSemanticLiveParameterizedCore.

(*---*) import RealOrder.

(* Live parameterized MS2 execution-owned failure mass lane. *)

op ms_rom_execution_owned_parameterized_failure_probability
  (x : ms_public_input) : real =
  mu1 (d_ms_rom_semantic_failure_state_choice_parameterized x) true.

lemma ms_rom_execution_owned_parameterized_failure_probability_eq_local_mass
  (x : ms_public_input) :
  ms_rom_execution_owned_parameterized_failure_probability x =
  ms_rom_local_failure_mass_parameterized.
proof.
rewrite /ms_rom_execution_owned_parameterized_failure_probability
        /ms_rom_local_failure_mass_parameterized.
by rewrite d_ms_rom_semantic_failure_state_choice_parameterizedE.
qed.

lemma ms_rom_execution_owned_parameterized_failure_probability_le_epsilon_ms_rom_programmability_parameterized
  (x : ms_public_input) :
  ms_rom_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
rewrite ms_rom_execution_owned_parameterized_failure_probability_eq_local_mass.
exact ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_parameterized.
qed.

lemma A_MS2_rom_programming_execution_owned_live_parameterized_bound
  (x : ms_public_input) :
  ms_rom_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
exact (ms_rom_execution_owned_parameterized_failure_probability_le_epsilon_ms_rom_programmability_parameterized x).
qed.

lemma ms_rom_public_observable_divergence_mass_le_execution_owned_live_parameterized_failure
  (x : ms_public_input) :
  mu (d_ms_rom_semantic_coupled_state_parameterized x)
    (ms_rom_public_observable_divergence_condition x) <=
  ms_rom_execution_owned_parameterized_failure_probability x.
proof.
have Hsub :
    mu (d_ms_rom_semantic_coupled_state_parameterized x)
      (ms_rom_public_observable_divergence_condition x) <=
    mu (d_ms_rom_semantic_coupled_state_parameterized x)
      (fun st : ms_rom_semantic_state =>
        ms_rom_semantic_failure_event st).
  apply mu_sub => st /=.
  by smt(ms_rom_public_observable_divergence_condition_implies_semantic_failure).
have Hmass :
    mu (d_ms_rom_semantic_coupled_state_parameterized x)
      (fun st : ms_rom_semantic_state =>
        ms_rom_semantic_failure_event st) =
    ms_rom_execution_owned_parameterized_failure_probability x.
  have Hmu1 :
      mu (d_ms_rom_semantic_failure_state_choice_parameterized x)
        (fun bad : bool => bad) =
      mu1 (d_ms_rom_semantic_failure_state_choice_parameterized x) true.
    apply/mu_eq=> bad /=.
    by case: bad.
  rewrite /ms_rom_execution_owned_parameterized_failure_probability.
  rewrite /d_ms_rom_semantic_failure_state_choice_parameterized dmapE /= in Hmu1.
  exact Hmu1.
rewrite -Hmass.
exact Hsub.
qed.