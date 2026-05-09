require import AllCore Distr.
require import Real.
require import StdOrder.
require import QssmTypes.
require import ParameterizedBudgetParameters.
require import SourceTypes SourceModel.
require import SourceBitnessDistributions.
require import SourceHashBindingSemanticBridge.
require import SourceHashBindingSemanticSlotMassParameterized.
require import SourceHashBindingSemanticLiveParameterizedCore.

(*---*) import RealOrder.

(* Live parameterized MS1 canonical failure mass lane. *)

op ms_hash_binding_execution_owned_parameterized_failure_probability
  (x : ms_public_input) : real =
  mu1 (d_ms_hash_binding_semantic_failure_state_choice_parameterized x) true.

lemma ms_hash_binding_execution_owned_parameterized_failure_probability_eq_local_mass
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x =
  ms_hash_binding_local_failure_mass_parameterized.
proof.
rewrite /ms_hash_binding_execution_owned_parameterized_failure_probability
        /ms_hash_binding_local_failure_mass_parameterized.
by rewrite d_ms_hash_binding_semantic_failure_state_choice_parameterizedE.
qed.

lemma ms_hash_binding_execution_owned_parameterized_failure_probability_eq_epsilon_ms_hash_binding_parameterized
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x =
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
rewrite ms_hash_binding_execution_owned_parameterized_failure_probability_eq_local_mass.
exact ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_parameterized.
qed.

lemma ms_hash_binding_execution_owned_parameterized_failure_probability_le_epsilon_ms_hash_binding_parameterized
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
rewrite ms_hash_binding_execution_owned_parameterized_failure_probability_eq_local_mass.
exact ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_parameterized.
qed.

lemma A_MS1_hash_binding_execution_owned_live_parameterized_bound
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_parameterized_failure_probability x <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
exact (ms_hash_binding_execution_owned_parameterized_failure_probability_le_epsilon_ms_hash_binding_parameterized x).
qed.

lemma ms_hash_binding_public_divergence_upper_pair_choice_mass_eq_local_upper_mass_live_parameterized
  (x : ms_public_input) :
  mu1 (d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized x) true =
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
rewrite d_ms_hash_binding_public_divergence_upper_pair_choice_parameterizedE.
exact ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized.
qed.

lemma ms_hash_binding_public_observable_divergence_implies_public_divergence_upper_event_parameterized
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_public_observable_divergence_condition
    (ms_hash_binding_semantic_state_of_category_source src category) =>
  ms_hash_binding_public_divergence_upper_category_event_parameterized category.
proof.
move=> Hdiv.
have Hupper :=
  ms_hash_binding_public_observable_divergence_implies_public_divergence_upper_event
    src category Hdiv.
rewrite /ms_hash_binding_public_divergence_upper_category_event_parameterized.
rewrite /ms_hash_binding_public_divergence_upper_category_event in Hupper.
by smt().
qed.

lemma ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_live_parameterized
  (x : ms_public_input) :
  mu (d_ms_hash_binding_semantic_coupled_state_parameterized x)
    ms_hash_binding_public_observable_divergence_condition <=
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
rewrite /d_ms_hash_binding_semantic_coupled_state_parameterized dmapE /mu /=.
have Hupper :
    mu ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
      (ms_hash_binding_public_observable_divergence_condition \o
        (fun (p : ms3a_bitness_layer_source *
                   BudgetParameters.ms_hash_binding_semantic_category) =>
           ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) <=
    mu ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_divergence_upper_category_event_parameterized (snd p)).
  apply mu_sub => p /=.
  exact (ms_hash_binding_public_observable_divergence_implies_public_divergence_upper_event_parameterized
    (fst p) (snd p)).
have Hmu1 :
    mu ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_divergence_upper_category_event_parameterized (snd p)) =
    mu1 (d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized x) true.
  rewrite /d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized.
  rewrite /mu1 dmapE /=.
  apply/mu_eq=> p /=.
  rewrite /(\o) /=.
  by case: (ms_hash_binding_public_divergence_upper_category_event_parameterized (snd p)).
have Hupper' :
    mu ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
      (ms_hash_binding_public_observable_divergence_condition \o
        (fun (p : ms3a_bitness_layer_source *
                   BudgetParameters.ms_hash_binding_semantic_category) =>
           ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) <=
    mu1 (d_ms_hash_binding_public_divergence_upper_pair_choice_parameterized x) true.
  by rewrite -Hmu1.
rewrite -(ms_hash_binding_public_divergence_upper_pair_choice_mass_eq_local_upper_mass_live_parameterized x).
exact Hupper'.
qed.

lemma ms_hash_binding_public_observable_divergence_mass_le_execution_owned_live_parameterized_failure
  (x : ms_public_input) :
  mu (d_ms_hash_binding_semantic_coupled_state_parameterized x)
    ms_hash_binding_public_observable_divergence_condition <=
  ms_hash_binding_execution_owned_parameterized_failure_probability x.
proof.
have Hupper :=
  ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_live_parameterized x.
rewrite ms_hash_binding_execution_owned_parameterized_failure_probability_eq_epsilon_ms_hash_binding_parameterized.
exact (ler_trans _ _ _ Hupper
  ms_hash_binding_local_public_divergence_upper_mass_le_epsilon_ms_hash_binding_parameterized).
qed.