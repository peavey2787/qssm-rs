require import QssmTypes.
require import AllCore Distr.
require import Real.
require import Ring.
require import SDist.
require import LESurface.
require import LEFsProgrammingFailureProbability.
require import LEFsProgrammingFailureProbabilityParameterized.
require import LEFsProgrammingSurface.
require import LEFsProgramming.
require BudgetParameters.
require ParameterizedBudgetParameters.

(* Parallel theorem-facing LE FS parameterized bridge.
   This leaves the existing semantic/demo FS bridge untouched and only adds a
   companion wrapper above the parameterized owner surface. *)

(* Compatibility-only alias lemma: this closes only because the current
  parameterized FS counts alias the live demo semantic counts. *)
lemma epsilon_le_fs_semantic_eq_epsilon_le_fs_parameterized :
  BudgetParameters.epsilon_le_fs_semantic =
  ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
rewrite BudgetParameters.epsilon_le_fs_semantic_closed_form.
rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
rewrite /ParameterizedBudgetParameters.le_fs_param_failure_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_total_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_query_collision_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_programming_collision_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_transcript_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_clean_count.
by rewrite /BudgetParameters.le_fs_failure_slot_count /BudgetParameters.le_fs_total_slot_count.
qed.

(* Main FS bridge below now avoids the compatibility-only semantic-to-
   parameterized equality by comparing the live bad-branch mass directly
   against the parameterized owner budget. *)
lemma le_fs_shadow_local_bad_branch_mass_le_parameterized_budget
  (x : qssm_public_input) (s : seed) :
  LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass <=
  ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
have -> :
    LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass =
    mu1 LEFsProgrammingSurface.d_le_fs_shadow_branch_choice true.
  rewrite /LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
  apply/mu_eq=> bad /=.
  by case: bad.
rewrite /LEFsProgrammingSurface.d_le_fs_shadow_branch_choice.
rewrite BudgetParameters.le_fs_semantic_branch_choice_mass_true.
rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
rewrite /ParameterizedBudgetParameters.le_fs_param_failure_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_total_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_query_collision_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_programming_collision_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_transcript_count.
rewrite /ParameterizedBudgetParameters.le_fs_param_clean_count.
rewrite /BudgetParameters.bad_slot_count /BudgetParameters.total_slot_count.
rewrite /BudgetParameters.le_fs_failure_slot_count /BudgetParameters.le_fs_total_slot_count.
by smt().
qed.

lemma le_fs_shadow_local_bad_branch_mass_le_parameterized_failure_probability
  (x : qssm_public_input) (s : seed) :
  LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass <=
  le_fs_failure_probability_parameterized x s.
proof.
rewrite (le_fs_failure_probability_eq_epsilon_le_fs_parameterized x s).
exact (le_fs_shadow_local_bad_branch_mass_le_parameterized_budget x s).
qed.

lemma A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s)
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s D Hr Hs Hfs.
have Hmass :=
  A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass x s D Hr Hs Hfs.
have Hbridge :=
  le_fs_shadow_local_bad_branch_mass_le_parameterized_budget x s.
by smt().
qed.