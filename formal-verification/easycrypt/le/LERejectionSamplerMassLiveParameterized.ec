require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import Ring.
require import SDist.
require import StdOrder.
require import LESurface.
require import LERejection.
require import LERejectionSamplerParameterizedCore.
require import ParameterizedMassHelpers.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

op le_rejection_parameterized_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  mu (dmap (d_le_rejection_parameterized_coupled_state x s)
       le_rejection_parameterized_reject_event)
    (fun (reject : bool) => reject).

op le_rejection_parameterized_ticket_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  mu1 d_le_rejection_parameterized_branch_choice true.

lemma count_range0_ge_suffix (bound total : int) :
  0 <= bound =>
  bound <= total =>
  count (fun slot : int => bound <= slot) (range 0 total) = total - bound.
proof.
move=> Hbound_nonneg Hbound_le_total.
have Hsplit : range 0 total = range 0 bound ++ range bound total.
  by apply (range_cat bound 0 total).
rewrite Hsplit count_cat.
have Hpre :
    count (fun slot : int => bound <= slot) (range 0 bound) = 0.
  apply count_pred0_eq_in=> slot Hslot.
  by smt(mem_range).
have Hsuf :
    count (fun slot : int => bound <= slot) (range bound total) =
    size (range bound total).
  apply count_predT_eq_in=> slot Hslot.
  by smt(mem_range).
rewrite Hpre Hsuf.
rewrite size_range.
by smt().
qed.

lemma d_le_rejection_parameterized_branch_choice_mass_true :
  mu1 d_le_rejection_parameterized_branch_choice true =
  ParameterizedBudgetParameters.le_rej_param_failure_count%r /
  ParameterizedBudgetParameters.le_rej_param_total_count%r.
proof.
rewrite /d_le_rejection_parameterized_branch_choice.
exact (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.le_rej_param_failure_count
  ParameterizedBudgetParameters.le_rej_param_total_count
  ParameterizedBudgetParameters.le_rej_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_rej_param_failure_count_le_total_count
  ParameterizedBudgetParameters.le_rej_param_total_count_pos).
qed.

lemma d_le_rejection_parameterized_branch_choice_mass_false :
  mu1 d_le_rejection_parameterized_branch_choice false =
  (ParameterizedBudgetParameters.le_rej_param_total_count -
   ParameterizedBudgetParameters.le_rej_param_failure_count)%r /
  ParameterizedBudgetParameters.le_rej_param_total_count%r.
proof.
rewrite /mu1 /d_le_rejection_parameterized_branch_choice dmapE /=.
have Heq :
    mu (drange 0 ParameterizedBudgetParameters.le_rej_param_total_count)
      (fun slot : int => pred1 false (slot < ParameterizedBudgetParameters.le_rej_param_failure_count)) =
    mu (drange 0 ParameterizedBudgetParameters.le_rej_param_total_count)
      (fun slot : int => ParameterizedBudgetParameters.le_rej_param_failure_count <= slot).
  apply mu_eq=> slot /=.
  by rewrite /pred1; case (slot < ParameterizedBudgetParameters.le_rej_param_failure_count); smt().
rewrite Heq.
rewrite drangeE.
rewrite (count_range0_ge_suffix
  ParameterizedBudgetParameters.le_rej_param_failure_count
  ParameterizedBudgetParameters.le_rej_param_total_count
  ParameterizedBudgetParameters.le_rej_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_rej_param_failure_count_le_total_count).
have -> :
    ParameterizedBudgetParameters.le_rej_param_total_count - 0 =
    ParameterizedBudgetParameters.le_rej_param_total_count by ring.
by [].
qed.

lemma le_rejection_parameterized_local_reject_branch_mass_is_true_mass :
  le_rejection_parameterized_local_reject_branch_mass =
  mu1 d_le_rejection_parameterized_branch_choice true.
proof.
rewrite /le_rejection_parameterized_local_reject_branch_mass.
have Hmu1 :
    mu d_le_rejection_parameterized_branch_choice (fun (reject : bool) => reject) =
    mu1 d_le_rejection_parameterized_branch_choice true.
  apply/mu_eq=> reject /=.
  by case: reject.
exact Hmu1.
qed.

lemma le_rejection_parameterized_local_reject_branch_mass_closed_form :
  le_rejection_parameterized_local_reject_branch_mass =
  ParameterizedBudgetParameters.le_rej_param_failure_count%r /
  ParameterizedBudgetParameters.le_rej_param_total_count%r.
proof.
rewrite le_rejection_parameterized_local_reject_branch_mass_is_true_mass.
exact d_le_rejection_parameterized_branch_choice_mass_true.
qed.

lemma le_rejection_parameterized_ticket_failure_probability_eq_epsilon_le_rej_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_parameterized_ticket_failure_probability x s =
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite /le_rejection_parameterized_ticket_failure_probability.
rewrite d_le_rejection_parameterized_branch_choice_mass_true.
rewrite ParameterizedBudgetParameters.epsilon_le_rej_parameterized_closed_form.
by [].
qed.

lemma le_rejection_parameterized_branch_choice_sdist_dunit_false_le_reject_branch_mass :
  sdist d_le_rejection_parameterized_branch_choice (dunit false) <=
  le_rejection_parameterized_local_reject_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE :
        mu d_le_rejection_parameterized_branch_choice E =
        mu d_le_rejection_parameterized_branch_choice predT.
      apply/mu_eq=> reject /=.
      by case: reject=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_rejection_parameterized_branch_choice = 1%r.
      exact (is_losslessP _ d_le_rejection_parameterized_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE :
      mu d_le_rejection_parameterized_branch_choice E =
      mu1 d_le_rejection_parameterized_branch_choice false.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE d_le_rejection_parameterized_branch_choice_mass_false.
  rewrite le_rejection_parameterized_local_reject_branch_mass_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE :
      mu d_le_rejection_parameterized_branch_choice E =
      mu1 d_le_rejection_parameterized_branch_choice true.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE d_le_rejection_parameterized_branch_choice_mass_true.
  rewrite le_rejection_parameterized_local_reject_branch_mass_closed_form.
  by smt().
have HE :
    mu d_le_rejection_parameterized_branch_choice E =
    mu d_le_rejection_parameterized_branch_choice pred0.
  apply/mu_eq=> reject /=.
  by case: reject=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_rejection_parameterized_local_reject_branch_mass_closed_form.
by smt().
qed.

lemma le_rejection_parameterized_failure_probability_exact_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_parameterized_failure_probability x s =
    le_rejection_parameterized_local_reject_branch_mass.
proof.
move=> x s.
rewrite /le_rejection_parameterized_failure_probability.
rewrite /LERejectionSamplerParameterizedCore.le_rejection_parameterized_local_reject_branch_mass.
rewrite (d_le_rejection_parameterized_reject_event_image_branch_choice x s).
by [].
qed.

lemma le_rejection_parameterized_failure_probability_eq_ticket_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_parameterized_failure_probability x s =
    le_rejection_parameterized_ticket_failure_probability x s.
proof.
move=> x s.
rewrite le_rejection_parameterized_failure_probability_exact_branch_mass.
rewrite le_rejection_parameterized_local_reject_branch_mass_is_true_mass.
by rewrite /le_rejection_parameterized_ticket_failure_probability.
qed.

lemma le_rejection_parameterized_failure_probability_le_epsilon_le_rej_parameterized :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_parameterized_failure_probability x s <=
    ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s.
rewrite (le_rejection_parameterized_failure_probability_eq_ticket_failure_probability x s).
rewrite (le_rejection_parameterized_ticket_failure_probability_eq_epsilon_le_rej_parameterized x s).
by [].
qed.

lemma A_LE_rejection_parameterized_shadow_post_marginal_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_parameterized_pre_marginal x s)
      (d_le_rejection_parameterized_post_marginal x s)
      <= le_rejection_parameterized_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_rejection_parameterized_pre_marginal_fixed_branch_imageE x s).
rewrite (d_le_rejection_parameterized_post_marginal_fixed_branch_imageE x s).
pose F := fun reject =>
  le_rejection_parameterized_branch_image_of_observable x s
    (LERealExecution.le_real_execution_observable x s) reject.
have Hmap :
  sdist (dmap (dunit false) F)
    (dmap d_le_rejection_parameterized_branch_choice F) <=
  sdist (dunit false) d_le_rejection_parameterized_branch_choice.
  exact (sdist_dmap (dunit false) d_le_rejection_parameterized_branch_choice F).
apply (ler_trans _ _ _ Hmap).
rewrite sdistC.
apply (ler_trans _ _ _
  le_rejection_parameterized_branch_choice_sdist_dunit_false_le_reject_branch_mass).
rewrite le_rejection_parameterized_failure_probability_exact_branch_mass.
by [].
qed.

lemma A_LE_rejection_parameterized_sampler_semantic_experiment_sdist_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s)
      (d_le_rejection_parameterized_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s _ _ _ _.
have -> : d_le_real_view x s = d_le_rejection_parameterized_pre_marginal x s.
  rewrite (d_le_rejection_parameterized_pre_marginal_matches_execution_view x s).
  by rewrite /LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_real_execution_view
    /LERejectionSamplerCore.d_le_rejection_real_execution_view.
have Hsdist :=
  A_LE_rejection_parameterized_shadow_post_marginal_sdist_le_failure_probability x s.
have Hbudget :=
  le_rejection_parameterized_failure_probability_le_epsilon_le_rej_parameterized x s.
by smt().
qed.

lemma A_LE_rejection_parameterized_sampler_semantic_sdist_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (d_le_parameterized_post_rejection_view x s)
      <= ParameterizedBudgetParameters.epsilon_le_rej_parameterized.
proof.
move=> x s Hr Hdef Hacc Hshape.
exact (A_LE_rejection_parameterized_sampler_semantic_experiment_sdist_bound
  x s Hr Hdef Hacc Hshape).
qed.