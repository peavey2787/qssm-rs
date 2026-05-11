require import QssmTypes.
require import AllCore Distr.
require import ParameterizedBudgetParameters ParameterizedMassHelpers.

(* Parallel parameterized LE rejection local mass owner.
   This keeps the existing demo semantic rejection lane untouched while
   exposing the same local failure-mass shape against the parameterized owner
   surface. *)

op le_rejection_shadow_semantic_ticket_failure_probability_parameterized
  (x : qssm_public_input) (s : seed) : real =
  mu1 (dmap (drange 0 ParameterizedBudgetParameters.le_rej_param_total_count)
    (fun slot : int => slot < ParameterizedBudgetParameters.le_rej_param_failure_count))
    true.

op le_rejection_shadow_semantic_failure_probability_parameterized
  (x : qssm_public_input) (s : seed) : real =
  le_rejection_shadow_semantic_ticket_failure_probability_parameterized x s.

lemma le_rejection_shadow_semantic_ticket_failure_probability_parameterized_eq_epsilon_le_rej_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_ticket_failure_probability_parameterized x s =
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite /le_rejection_shadow_semantic_ticket_failure_probability_parameterized.
rewrite (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.le_rej_param_failure_count
  ParameterizedBudgetParameters.le_rej_param_total_count
  ParameterizedBudgetParameters.le_rej_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_rej_param_failure_count_le_total_count
  ParameterizedBudgetParameters.le_rej_param_total_count_pos).
rewrite ParameterizedBudgetParameters.epsilon_le_rej_parameterized_closed_form.
by [].
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability_parameterized x s =
    le_rejection_shadow_semantic_ticket_failure_probability_parameterized x s.
proof.
by move=> x s; rewrite /le_rejection_shadow_semantic_failure_probability_parameterized.
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability_parameterized x s =
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability_parameterized x s).
exact (le_rejection_shadow_semantic_ticket_failure_probability_parameterized_eq_epsilon_le_rej_parameterized x s).
qed.

lemma le_rejection_shadow_semantic_failure_probability_le_epsilon_le_rej_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability_parameterized x s <=
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_parameterized x s).
by [].
qed.