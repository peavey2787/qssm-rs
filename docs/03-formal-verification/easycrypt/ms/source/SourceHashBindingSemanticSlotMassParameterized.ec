require import AllCore Int List Distr.
require import BudgetParameters.
require import ParameterizedBudgetParameters ParameterizedMassHelpers.
import Ring.IntID StdOrder.IntOrder.

(* Parallel parameterized MS1 local slot/mass owner.
   This keeps the existing demo semantic lane untouched while proving the
   local failure mass and public-divergence upper mass against the
   parameterized owner surface. *)

op ms_hash_binding_semantic_category_of_slot_parameterized
  (slot : int) : BudgetParameters.ms_hash_binding_semantic_category =
  if slot < ParameterizedBudgetParameters.ms1_param_collision_count then
    BudgetParameters.MSHashBindingSemanticCollision
  else if slot <
      ParameterizedBudgetParameters.ms1_param_collision_count +
      ParameterizedBudgetParameters.ms1_param_malformed_binding_count then
    BudgetParameters.MSHashBindingSemanticMalformedBinding
  else if slot < ParameterizedBudgetParameters.ms1_param_failure_count then
    BudgetParameters.MSHashBindingSemanticTranscriptMismatch
  else BudgetParameters.MSHashBindingSemanticClean.

op ms_hash_binding_semantic_bad_slot_parameterized (slot : int) : bool =
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
    (ms_hash_binding_semantic_category_of_slot_parameterized slot).

op d_ms_hash_binding_semantic_slot_choice_parameterized : int distr =
  drange 0 ParameterizedBudgetParameters.ms1_param_total_count.

op d_ms_hash_binding_semantic_failure_choice_parameterized : bool distr =
  dmap d_ms_hash_binding_semantic_slot_choice_parameterized
    ms_hash_binding_semantic_bad_slot_parameterized.

lemma ms_hash_binding_semantic_bad_slot_parameterized_thresholdE (slot : int) :
  ms_hash_binding_semantic_bad_slot_parameterized slot =
  (slot < ParameterizedBudgetParameters.ms1_param_failure_count).
proof.
rewrite /ms_hash_binding_semantic_bad_slot_parameterized.
rewrite /ms_hash_binding_semantic_category_of_slot_parameterized.
rewrite /BudgetParameters.ms_hash_binding_semantic_category_is_failure /pred1 /=.
rewrite /ParameterizedBudgetParameters.ms1_param_failure_count.
by case (slot < ParameterizedBudgetParameters.ms1_param_collision_count)=> //=;
   case (slot < ParameterizedBudgetParameters.ms1_param_collision_count +
                ParameterizedBudgetParameters.ms1_param_malformed_binding_count)=> //=;
   smt().
qed.

lemma ms_hash_binding_semantic_failure_choice_mass_true_parameterized :
  mu1 d_ms_hash_binding_semantic_failure_choice_parameterized true =
  ParameterizedBudgetParameters.ms1_param_failure_count%r /
  ParameterizedBudgetParameters.ms1_param_total_count%r.
proof.
have Hmap :
    d_ms_hash_binding_semantic_failure_choice_parameterized =
    dmap d_ms_hash_binding_semantic_slot_choice_parameterized
      (fun slot : int => slot < ParameterizedBudgetParameters.ms1_param_failure_count).
  rewrite /d_ms_hash_binding_semantic_failure_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  by rewrite ms_hash_binding_semantic_bad_slot_parameterized_thresholdE.
rewrite Hmap.
exact (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.ms1_param_failure_count
  ParameterizedBudgetParameters.ms1_param_total_count
  ParameterizedBudgetParameters.ms1_param_failure_count_nonneg
  ParameterizedBudgetParameters.ms1_param_failure_count_le_total_count
  ParameterizedBudgetParameters.ms1_param_total_count_pos).
qed.

op ms_hash_binding_local_failure_mass_parameterized : real =
  mu1 d_ms_hash_binding_semantic_failure_choice_parameterized true.

lemma ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_parameterized :
  ms_hash_binding_local_failure_mass_parameterized =
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
rewrite /ms_hash_binding_local_failure_mass_parameterized.
rewrite ms_hash_binding_semantic_failure_choice_mass_true_parameterized.
rewrite ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized_closed_form.
by [].
qed.

lemma ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_parameterized :
  ms_hash_binding_local_failure_mass_parameterized <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
rewrite ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_parameterized.
by [].
qed.

op ms_hash_binding_public_divergence_upper_category_event_parameterized
  (category : BudgetParameters.ms_hash_binding_semantic_category) : bool =
  pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category ||
  pred1 BudgetParameters.MSHashBindingSemanticTranscriptMismatch category.

op ms_hash_binding_public_divergence_upper_slot_parameterized (slot : int) : bool =
  ms_hash_binding_public_divergence_upper_category_event_parameterized
    (ms_hash_binding_semantic_category_of_slot_parameterized slot).

op d_ms_hash_binding_public_divergence_upper_choice_parameterized : bool distr =
  dmap d_ms_hash_binding_semantic_slot_choice_parameterized
    ms_hash_binding_public_divergence_upper_slot_parameterized.

op ms_hash_binding_local_public_divergence_upper_mass_parameterized : real =
  (ParameterizedBudgetParameters.ms1_param_malformed_binding_count +
   ParameterizedBudgetParameters.ms1_param_transcript_count)%r /
  ParameterizedBudgetParameters.ms1_param_total_count%r.

lemma ms_hash_binding_public_divergence_upper_slot_parameterized_intervalE (slot : int) :
  ms_hash_binding_public_divergence_upper_slot_parameterized slot =
  (ParameterizedBudgetParameters.ms1_param_collision_count <= slot /\
   slot < ParameterizedBudgetParameters.ms1_param_failure_count).
proof.
rewrite /ms_hash_binding_public_divergence_upper_slot_parameterized.
rewrite /ms_hash_binding_public_divergence_upper_category_event_parameterized.
rewrite /ms_hash_binding_semantic_category_of_slot_parameterized /pred1 /=.
rewrite /ParameterizedBudgetParameters.ms1_param_failure_count.
by case (slot < ParameterizedBudgetParameters.ms1_param_collision_count)=> //=;
   case (slot < ParameterizedBudgetParameters.ms1_param_collision_count +
                ParameterizedBudgetParameters.ms1_param_malformed_binding_count)=> //=;
   smt().
qed.

lemma ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_parameterized :
  mu1 d_ms_hash_binding_public_divergence_upper_choice_parameterized true =
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
have Hmap :
    d_ms_hash_binding_public_divergence_upper_choice_parameterized =
    dmap d_ms_hash_binding_semantic_slot_choice_parameterized
      (fun slot : int =>
         ParameterizedBudgetParameters.ms1_param_collision_count <= slot /\
         slot < ParameterizedBudgetParameters.ms1_param_failure_count).
  rewrite /d_ms_hash_binding_public_divergence_upper_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  by rewrite ms_hash_binding_public_divergence_upper_slot_parameterized_intervalE.
rewrite Hmap.
rewrite /d_ms_hash_binding_semantic_slot_choice_parameterized.
have Hcollision_le_failure :
    ParameterizedBudgetParameters.ms1_param_collision_count <=
    ParameterizedBudgetParameters.ms1_param_failure_count.
  by smt(ParameterizedBudgetParameters.ms1_param_failure_count_component_sum
         ParameterizedBudgetParameters.ms1_param_malformed_binding_count_nonneg
         ParameterizedBudgetParameters.ms1_param_transcript_count_nonneg).
rewrite (ParameterizedMassHelpers.drange_pred_true_mass
  ParameterizedBudgetParameters.ms1_param_total_count
  (fun slot : int =>
     ParameterizedBudgetParameters.ms1_param_collision_count <= slot /\
     slot < ParameterizedBudgetParameters.ms1_param_failure_count)
  ParameterizedBudgetParameters.ms1_param_total_count_pos).
rewrite (ParameterizedMassHelpers.count_range0_interval
  ParameterizedBudgetParameters.ms1_param_collision_count
  ParameterizedBudgetParameters.ms1_param_failure_count
  ParameterizedBudgetParameters.ms1_param_total_count
  ParameterizedBudgetParameters.ms1_param_collision_count_nonneg
  Hcollision_le_failure
  ParameterizedBudgetParameters.ms1_param_failure_count_le_total_count).
rewrite /ms_hash_binding_local_public_divergence_upper_mass_parameterized.
rewrite /ParameterizedBudgetParameters.ms1_param_failure_count.
by smt().
qed.

lemma ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass_subset_parameterized :
  mu1 d_ms_hash_binding_public_divergence_upper_choice_parameterized true =
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
have Hmap :
    d_ms_hash_binding_public_divergence_upper_choice_parameterized =
    dmap d_ms_hash_binding_semantic_slot_choice_parameterized
      (fun slot : int =>
         slot \in range ParameterizedBudgetParameters.ms1_param_collision_count
                        ParameterizedBudgetParameters.ms1_param_failure_count).
  rewrite /d_ms_hash_binding_public_divergence_upper_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  rewrite ms_hash_binding_public_divergence_upper_slot_parameterized_intervalE.
  by smt(mem_range).
rewrite Hmap.
rewrite /d_ms_hash_binding_semantic_slot_choice_parameterized.
rewrite (ParameterizedMassHelpers.drange_subset_true_mass
  ParameterizedBudgetParameters.ms1_param_total_count
  (range ParameterizedBudgetParameters.ms1_param_collision_count
         ParameterizedBudgetParameters.ms1_param_failure_count)
  ParameterizedBudgetParameters.ms1_param_total_count_pos).
have Hcollision_le_failure :
    ParameterizedBudgetParameters.ms1_param_collision_count <=
    ParameterizedBudgetParameters.ms1_param_failure_count.
  by smt(ParameterizedBudgetParameters.ms1_param_failure_count_component_sum
         ParameterizedBudgetParameters.ms1_param_malformed_binding_count_nonneg
         ParameterizedBudgetParameters.ms1_param_transcript_count_nonneg).
have Hcount_eq :
    count (fun slot : int =>
       slot \in range ParameterizedBudgetParameters.ms1_param_collision_count
                      ParameterizedBudgetParameters.ms1_param_failure_count)
      (range 0 ParameterizedBudgetParameters.ms1_param_total_count) =
    count (fun slot : int =>
       ParameterizedBudgetParameters.ms1_param_collision_count <= slot /\
       slot < ParameterizedBudgetParameters.ms1_param_failure_count)
      (range 0 ParameterizedBudgetParameters.ms1_param_total_count).
  apply eq_count=> slot /=.
  by rewrite mem_range.
rewrite Hcount_eq.
rewrite (ParameterizedMassHelpers.count_range0_interval
  ParameterizedBudgetParameters.ms1_param_collision_count
  ParameterizedBudgetParameters.ms1_param_failure_count
  ParameterizedBudgetParameters.ms1_param_total_count
  ParameterizedBudgetParameters.ms1_param_collision_count_nonneg
  Hcollision_le_failure
  ParameterizedBudgetParameters.ms1_param_failure_count_le_total_count).
rewrite /ms_hash_binding_local_public_divergence_upper_mass_parameterized.
rewrite /ParameterizedBudgetParameters.ms1_param_failure_count.
by smt().
qed.

lemma ms_hash_binding_local_public_divergence_upper_mass_le_epsilon_ms_hash_binding_parameterized :
  ms_hash_binding_local_public_divergence_upper_mass_parameterized <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
rewrite /ms_hash_binding_local_public_divergence_upper_mass_parameterized.
rewrite ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized_closed_form.
rewrite /ParameterizedBudgetParameters.ms1_param_failure_count.
by smt(ParameterizedBudgetParameters.ms1_param_collision_count_nonneg
       ParameterizedBudgetParameters.ms1_param_total_count_pos).
qed.