require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LERealExecution.
require import LERejectionSamplerCore.
require import LERejectionSamplerSemanticMarginals.
require BudgetParameters.

(*---*) import RealOrder.

op le_rejection_shadow_semantic_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_rejection_shadow_semantic_coupled_state x s)
       le_rejection_shadow_reject_event)
    (fun (reject : bool) => reject).

op le_rejection_shadow_semantic_ticket_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability x s.

lemma le_rejection_shadow_semantic_branch_choice_sdist_dunit_false_le_reject_branch_mass :
  sdist d_le_rejection_shadow_semantic_branch_choice (dunit false) <=
  le_rejection_shadow_semantic_local_reject_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE :
        mu d_le_rejection_shadow_semantic_branch_choice E =
        mu d_le_rejection_shadow_semantic_branch_choice predT.
      apply/mu_eq=> reject /=.
      by case: reject=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_rejection_shadow_semantic_branch_choice = 1%r.
      exact (is_losslessP _ le_rejection_shadow_semantic_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE :
      mu d_le_rejection_shadow_semantic_branch_choice E =
      mu1 d_le_rejection_shadow_semantic_branch_choice false.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE le_rejection_shadow_semantic_branch_choice_mass_false.
  rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE :
      mu d_le_rejection_shadow_semantic_branch_choice E =
      mu1 d_le_rejection_shadow_semantic_branch_choice true.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE le_rejection_shadow_semantic_branch_choice_mass_true.
  rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
  by smt().
have HE :
    mu d_le_rejection_shadow_semantic_branch_choice E =
    mu d_le_rejection_shadow_semantic_branch_choice pred0.
  apply/mu_eq=> reject /=.
  by case: reject=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
by smt().
qed.

lemma le_rejection_shadow_semantic_failure_probability_exact_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    le_rejection_shadow_semantic_local_reject_branch_mass.
proof.
move=> x s.
rewrite /le_rejection_shadow_semantic_failure_probability.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_local_reject_branch_mass.
rewrite (d_le_rejection_shadow_semantic_reject_event_image_branch_choice x s).
by [].
qed.

lemma le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_ticket_failure_probability x s =
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite /le_rejection_shadow_semantic_ticket_failure_probability.
exact (LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    le_rejection_shadow_semantic_ticket_failure_probability x s.
proof.
move=> x s.
rewrite le_rejection_shadow_semantic_failure_probability_exact_branch_mass.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_eq_epsilon.
rewrite -(le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
by [].
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability x s).
exact (le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
qed.

lemma A_LE_rejection_shadow_semantic_failure_probability_le_semantic_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s <=
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic x s).
by [].
qed.

lemma A_LE_rejection_shadow_semantic_post_marginal_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_shadow_semantic_pre_marginal x s)
      (d_le_rejection_shadow_semantic_post_marginal x s)
      <= le_rejection_shadow_semantic_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_pre_marginal_fixed_branch_imageE x s).
rewrite (d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE x s).
pose F := fun reject =>
  le_rejection_shadow_semantic_branch_image_of_observable x s
    (le_real_execution_observable x s) reject.
have Hmap :
  sdist (dmap (dunit false) F)
    (dmap d_le_rejection_shadow_semantic_branch_choice F) <=
  sdist (dunit false) d_le_rejection_shadow_semantic_branch_choice.
  exact (sdist_dmap (dunit false) d_le_rejection_shadow_semantic_branch_choice F).
apply (ler_trans _ _ _ Hmap).
rewrite sdistC.
apply (ler_trans _ _ _
  le_rejection_shadow_semantic_branch_choice_sdist_dunit_false_le_reject_branch_mass).
rewrite le_rejection_shadow_semantic_failure_probability_exact_branch_mass.
by [].
qed.

lemma A_LE_rejection_shadow_semantic_post_marginal_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_shadow_semantic_pre_marginal x s)
      (d_le_rejection_shadow_semantic_post_marginal x s)
      <= BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
have Hsdist :=
  A_LE_rejection_shadow_semantic_post_marginal_sdist_le_failure_probability x s.
have Hbudget :=
  A_LE_rejection_shadow_semantic_failure_probability_le_semantic_budget x s.
by smt().
qed.