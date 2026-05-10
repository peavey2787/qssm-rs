require import AllCore Int List Distr.
require import BudgetParameters.
require import ParameterizedBudgetParameters ParameterizedMassHelpers.
import Ring.IntID StdOrder.IntOrder Range.

(* Parallel parameterized MS2 local slot/mass owner.
   This keeps the existing demo semantic lane untouched while proving the same
   local failure-mass shape against the parameterized owner surface. *)

op ms_rom_semantic_slot_support_parameterized : int list =
  range 0 ParameterizedBudgetParameters.ms2_param_total_count.

op ms_rom_semantic_category_of_slot_parameterized
  (slot : int) : BudgetParameters.ms_rom_semantic_category =
  if slot < ParameterizedBudgetParameters.ms2_param_global_digest_count then
    BudgetParameters.MSROMSemanticQueryCollision
  else if slot <
      ParameterizedBudgetParameters.ms2_param_global_digest_count +
      ParameterizedBudgetParameters.ms2_param_query_digest_count then
    BudgetParameters.MSROMSemanticProgrammingCollision
  else if slot < ParameterizedBudgetParameters.ms2_param_failure_count then
    BudgetParameters.MSROMSemanticTranscriptMismatch
  else BudgetParameters.MSROMSemanticClean.

op ms_rom_semantic_bad_slot_parameterized (slot : int) : bool =
  BudgetParameters.ms_rom_semantic_category_is_failure
    (ms_rom_semantic_category_of_slot_parameterized slot).

op d_ms_rom_semantic_slot_choice_parameterized : int distr =
  drange 0 ParameterizedBudgetParameters.ms2_param_total_count.

op d_ms_rom_semantic_failure_choice_parameterized : bool distr =
  dmap d_ms_rom_semantic_slot_choice_parameterized
    ms_rom_semantic_bad_slot_parameterized.

lemma ms_rom_semantic_bad_slot_parameterized_thresholdE (slot : int) :
  ms_rom_semantic_bad_slot_parameterized slot =
  (slot < ParameterizedBudgetParameters.ms2_param_failure_count).
proof.
rewrite /ms_rom_semantic_bad_slot_parameterized.
rewrite /ms_rom_semantic_category_of_slot_parameterized.
rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
rewrite /ParameterizedBudgetParameters.ms2_param_failure_count.
by case (slot < ParameterizedBudgetParameters.ms2_param_global_digest_count)=> //=;
   case (slot < ParameterizedBudgetParameters.ms2_param_global_digest_count +
                ParameterizedBudgetParameters.ms2_param_query_digest_count)=> //=;
   smt().
qed.

lemma ms_rom_semantic_failure_choice_mass_true_parameterized :
  mu1 d_ms_rom_semantic_failure_choice_parameterized true =
  ParameterizedBudgetParameters.ms2_param_failure_count%r /
  ParameterizedBudgetParameters.ms2_param_total_count%r.
proof.
have Hmap :
    d_ms_rom_semantic_failure_choice_parameterized =
    dmap d_ms_rom_semantic_slot_choice_parameterized
      (fun slot : int => slot < ParameterizedBudgetParameters.ms2_param_failure_count).
  rewrite /d_ms_rom_semantic_failure_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  by rewrite ms_rom_semantic_bad_slot_parameterized_thresholdE.
rewrite Hmap.
exact (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.ms2_param_failure_count
  ParameterizedBudgetParameters.ms2_param_total_count
  ParameterizedBudgetParameters.ms2_param_failure_count_nonneg
  ParameterizedBudgetParameters.ms2_param_failure_count_le_total_count
  ParameterizedBudgetParameters.ms2_param_total_count_pos).
qed.

op ms_rom_local_failure_mass_parameterized : real =
  mu1 d_ms_rom_semantic_failure_choice_parameterized true.

lemma ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_parameterized :
  ms_rom_local_failure_mass_parameterized =
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
rewrite /ms_rom_local_failure_mass_parameterized.
rewrite ms_rom_semantic_failure_choice_mass_true_parameterized.
rewrite ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized_closed_form.
by [].
qed.

lemma ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_parameterized :
  ms_rom_local_failure_mass_parameterized <=
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
rewrite ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_parameterized.
by [].
qed.