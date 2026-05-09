require import AllCore Int List Distr.
require import Real.
require import QssmTypes.
require import BudgetParameters.
require import ParameterizedBudgetParameters.
require import TranscriptObservable.
require import SourceTypes SourceModel.
require import SourceConstructors SourcePayloadDistributions.
require import SourceBitnessDistributions SourceObservableDistributions.
require import SourceHashBindingSemanticBridge.
require import SourceHashBindingSemanticSlotMassParameterized.
require import SourceHashBindingSemanticLiveParameterizedCore.
require import SourceHashBindingSemanticLiveParameterizedMass.
import Ring.IntID StdOrder.IntOrder Range.

(* Parallel MS1 semantic bridge against the parameterized owner surface.
  The canonical execution-owned failure lane and the staged MS1
  public-divergence upper lane both now run on the live parameterized owner. *)

lemma ms_hash_binding_local_failure_mass_le_parameterized_budget :
  ms_hash_binding_local_failure_mass_parameterized <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
exact ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_parameterized.
qed.

lemma ms_hash_binding_execution_owned_parameterized_failure_probability_eq_epsilon_ms_hash_binding_parameterized
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x =
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
exact (SourceHashBindingSemanticLiveParameterizedMass.ms_hash_binding_execution_owned_parameterized_failure_probability_eq_epsilon_ms_hash_binding_parameterized x).
qed.

(* Slice 1 leaves the staged public-divergence lane on the demo semantic
   coupled state and demo local upper mass. *)
lemma ms_hash_binding_public_divergence_upper_pair_choice_mass_eq_local_upper_mass_parameterized
  (x : ms_public_input) :
  mu1 (d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized x) true =
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
exact (SourceHashBindingSemanticLiveParameterizedMass.ms_hash_binding_public_divergence_upper_pair_choice_mass_eq_local_upper_mass_live_parameterized x).
qed.

lemma ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_parameterized
  (x : ms_public_input) :
  mu (d_ms_hash_binding_semantic_coupled_state_parameterized x)
    ms_hash_binding_public_observable_divergence_condition <=
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
exact (SourceHashBindingSemanticLiveParameterizedMass.ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_live_parameterized x).
qed.

lemma A_MS1_hash_binding_execution_owned_parameterized_bound
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
exact (SourceHashBindingSemanticLiveParameterizedMass.A_MS1_hash_binding_execution_owned_live_parameterized_bound x).
qed.