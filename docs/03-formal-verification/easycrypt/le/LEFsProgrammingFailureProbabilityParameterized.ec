require import QssmTypes.
require import AllCore Distr.
require import ParameterizedBudgetParameters ParameterizedMassHelpers.

(* Parallel parameterized LE FS local failure-probability owner.
   This keeps the existing demo semantic FS lane untouched while exposing the
   same prefix-failure mass shape against the parameterized owner surface. *)

op le_fs_failure_probability_parameterized
  (x : qssm_public_input) (s : seed) : real =
  mu1 (dmap (drange 0 ParameterizedBudgetParameters.le_fs_param_total_count)
    (fun slot : int => slot < ParameterizedBudgetParameters.le_fs_param_failure_count))
    true.

lemma le_fs_failure_probability_eq_epsilon_le_fs_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_fs_failure_probability_parameterized x s =
    ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s.
rewrite /le_fs_failure_probability_parameterized.
rewrite (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.le_fs_param_failure_count
  ParameterizedBudgetParameters.le_fs_param_total_count
  ParameterizedBudgetParameters.le_fs_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_fs_param_failure_count_le_total_count
  ParameterizedBudgetParameters.le_fs_param_total_count_pos).
rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
by [].
qed.

lemma le_fs_failure_probability_le_epsilon_le_fs_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_fs_failure_probability_parameterized x s <=
    ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s.
rewrite (le_fs_failure_probability_eq_epsilon_le_fs_parameterized x s).
by [].
qed.