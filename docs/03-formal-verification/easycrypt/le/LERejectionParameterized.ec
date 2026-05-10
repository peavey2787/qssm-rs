require import QssmTypes.
require import AllCore Distr.
require import Real.
require import Ring.
require import SDist.
require import LESurface.
require import LERejection.
require import LERejectionSamplerParameterizedCore.
require import LERejectionSamplerMassLiveParameterized.
require ParameterizedBudgetParameters.

(* Parallel theorem-facing LE rejection parameterized bridge.
   This leaves the demo semantic rejection route unchanged and forwards the
   parameterized theorem surface to the new live parameterized sampler lane. *)

lemma A_LE_rejection_shadow_semantic_failure_probability_le_parameterized_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_parameterized_failure_probability x s <=
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
exact le_rejection_parameterized_failure_probability_le_epsilon_le_rej_parameterized.
qed.

lemma A_LE_rejection_sampler_semantic_experiment_sdist_parameterized_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s)
      (d_le_rejection_parameterized_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
exact A_LE_rejection_parameterized_sampler_semantic_experiment_sdist_bound.
qed.

lemma A_LE_rejection_sampler_semantic_sdist_parameterized_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (d_le_parameterized_post_rejection_view x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
exact A_LE_rejection_parameterized_sampler_semantic_sdist_bound.
qed.