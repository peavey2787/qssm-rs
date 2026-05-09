require import QssmTypes.
require import AllCore Distr.
require import Real.
require import Ring.
require import SDist.
require import LESurface.
require import LERejectionSampler.
require import LERejectionSamplerMassParameterized.
require import LERejection.
require BudgetParameters.
require ParameterizedBudgetParameters.

(* Parallel theorem-facing LE rejection parameterized bridge.
   This leaves the existing semantic/demo bridge untouched and only adds a
   companion wrapper above the parameterized owner surface. *)

(* Compatibility-only alias lemma: this closes only because the current
  parameterized rejection counts alias the live demo semantic counts. *)
lemma epsilon_le_rej_semantic_eq_epsilon_le_rej_parameterized :
  BudgetParameters.epsilon_le_rej_semantic =
  ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
rewrite BudgetParameters.epsilon_le_rej_semantic_closed_form.
rewrite ParameterizedBudgetParameters.epsilon_le_rej_parameterized_closed_form.
rewrite /ParameterizedBudgetParameters.le_rej_param_failure_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_total_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_soft_repair_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_hard_repair_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_invalid_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_accept_count.
by rewrite /BudgetParameters.le_rej_failure_slot_count /BudgetParameters.le_rej_total_slot_count.
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_parameterized
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_failure_probability x s =
  le_rejection_shadow_semantic_failure_probability_parameterized x s.
proof.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic x s).
rewrite (le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_parameterized x s).
exact epsilon_le_rej_semantic_eq_epsilon_le_rej_parameterized.
qed.

(* Main rejection bridge below now avoids the compatibility-only semantic-to-
   parameterized equality by comparing the live semantic ticket-failure law
   directly against the parameterized owner budget. *)
lemma le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_ticket_failure_probability x s <=
  ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
rewrite (le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
rewrite BudgetParameters.epsilon_le_rej_semantic_closed_form.
rewrite ParameterizedBudgetParameters.epsilon_le_rej_parameterized_closed_form.
rewrite /ParameterizedBudgetParameters.le_rej_param_failure_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_total_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_soft_repair_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_hard_repair_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_invalid_count.
rewrite /ParameterizedBudgetParameters.le_rej_param_accept_count.
rewrite /BudgetParameters.le_rej_failure_slot_count /BudgetParameters.le_rej_total_slot_count.
by smt().
qed.

lemma A_LE_rejection_shadow_semantic_failure_probability_le_parameterized_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s <=
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability x s).
exact (le_rejection_shadow_semantic_ticket_failure_probability_le_parameterized_budget x s).
qed.

lemma A_LE_rejection_sampler_semantic_experiment_sdist_parameterized_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s)
      (d_le_rejection_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s Hr Hdef Hacc Hshape.
have Hshadow :=
  A_LE_rejection_sampler_semantic_experiment_sdist_le_failure_probability
    x s Hr Hdef Hacc Hshape.
have Hbudget :=
  A_LE_rejection_shadow_semantic_failure_probability_le_parameterized_budget x s.
by smt().
qed.

lemma A_LE_rejection_sampler_semantic_sdist_parameterized_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (LERejectionSampler.d_le_semantic_post_rejection_view x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s Hr Hdef Hacc Hshape.
exact (A_LE_rejection_sampler_semantic_experiment_sdist_parameterized_bound
  x s Hr Hdef Hacc Hshape).
qed.