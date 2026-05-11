require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import Ring.
require import SDist.
require import StdOrder.
require import LESurface.
require import LEFsProgrammingSurface.
require import LEFsProgrammingLiveParameterizedCore.
require import ParameterizedMassHelpers.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

op le_fs_parameterized_local_bad_branch_mass : real =
  mu d_le_fs_parameterized_shadow_branch_choice (fun (bad : bool) => bad).

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

lemma d_le_fs_parameterized_shadow_branch_choice_mass_true :
  mu1 d_le_fs_parameterized_shadow_branch_choice true =
  ParameterizedBudgetParameters.le_fs_param_failure_count%r /
  ParameterizedBudgetParameters.le_fs_param_total_count%r.
proof.
rewrite /d_le_fs_parameterized_shadow_branch_choice.
exact (ParameterizedMassHelpers.drange_prefix_true_mass
  ParameterizedBudgetParameters.le_fs_param_failure_count
  ParameterizedBudgetParameters.le_fs_param_total_count
  ParameterizedBudgetParameters.le_fs_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_fs_param_failure_count_le_total_count
  ParameterizedBudgetParameters.le_fs_param_total_count_pos).
qed.

lemma d_le_fs_parameterized_shadow_branch_choice_mass_false :
  mu1 d_le_fs_parameterized_shadow_branch_choice false =
  (ParameterizedBudgetParameters.le_fs_param_total_count -
   ParameterizedBudgetParameters.le_fs_param_failure_count)%r /
  ParameterizedBudgetParameters.le_fs_param_total_count%r.
proof.
rewrite /mu1 /d_le_fs_parameterized_shadow_branch_choice dmapE /=.
have Heq :
    mu (drange 0 ParameterizedBudgetParameters.le_fs_param_total_count)
      (fun slot : int => pred1 false (slot < ParameterizedBudgetParameters.le_fs_param_failure_count)) =
    mu (drange 0 ParameterizedBudgetParameters.le_fs_param_total_count)
      (fun slot : int => ParameterizedBudgetParameters.le_fs_param_failure_count <= slot).
  apply mu_eq=> slot /=.
  by rewrite /pred1; case (slot < ParameterizedBudgetParameters.le_fs_param_failure_count); smt().
rewrite Heq.
rewrite drangeE.
rewrite (count_range0_ge_suffix
  ParameterizedBudgetParameters.le_fs_param_failure_count
  ParameterizedBudgetParameters.le_fs_param_total_count
  ParameterizedBudgetParameters.le_fs_param_failure_count_nonneg
  ParameterizedBudgetParameters.le_fs_param_failure_count_le_total_count).
have -> :
    ParameterizedBudgetParameters.le_fs_param_total_count - 0 =
    ParameterizedBudgetParameters.le_fs_param_total_count by ring.
by [].
qed.

lemma le_fs_parameterized_local_bad_branch_mass_is_true_mass :
  le_fs_parameterized_local_bad_branch_mass =
  mu1 d_le_fs_parameterized_shadow_branch_choice true.
proof.
rewrite /le_fs_parameterized_local_bad_branch_mass.
apply/mu_eq=> bad /=.
by case: bad.
qed.

lemma le_fs_parameterized_local_bad_branch_mass_eq_epsilon_le_fs_parameterized :
  le_fs_parameterized_local_bad_branch_mass =
  ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
rewrite le_fs_parameterized_local_bad_branch_mass_is_true_mass.
rewrite d_le_fs_parameterized_shadow_branch_choice_mass_true.
rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
by [].
qed.

lemma le_fs_parameterized_local_bad_branch_mass_le_epsilon_le_fs_parameterized :
  le_fs_parameterized_local_bad_branch_mass <=
  ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
rewrite le_fs_parameterized_local_bad_branch_mass_eq_epsilon_le_fs_parameterized.
by [].
qed.

lemma le_fs_parameterized_shadow_branch_choice_sdist_dunit_false_le_bad_branch_mass :
  sdist d_le_fs_parameterized_shadow_branch_choice (dunit false) <=
  le_fs_parameterized_local_bad_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE :
        mu d_le_fs_parameterized_shadow_branch_choice E =
        mu d_le_fs_parameterized_shadow_branch_choice predT.
      apply/mu_eq=> bad /=.
      by case: bad=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_fs_parameterized_shadow_branch_choice = 1%r.
      exact (is_losslessP _ d_le_fs_parameterized_shadow_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE :
      mu d_le_fs_parameterized_shadow_branch_choice E =
      mu1 d_le_fs_parameterized_shadow_branch_choice false.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE d_le_fs_parameterized_shadow_branch_choice_mass_false.
  rewrite le_fs_parameterized_local_bad_branch_mass_eq_epsilon_le_fs_parameterized.
  rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE :
      mu d_le_fs_parameterized_shadow_branch_choice E =
      mu1 d_le_fs_parameterized_shadow_branch_choice true.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE d_le_fs_parameterized_shadow_branch_choice_mass_true.
  rewrite le_fs_parameterized_local_bad_branch_mass_eq_epsilon_le_fs_parameterized.
  rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
  by smt().
have HE :
    mu d_le_fs_parameterized_shadow_branch_choice E =
    mu d_le_fs_parameterized_shadow_branch_choice pred0.
  apply/mu_eq=> bad /=.
  by case: bad=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_fs_parameterized_local_bad_branch_mass_eq_epsilon_le_fs_parameterized.
rewrite ParameterizedBudgetParameters.epsilon_le_fs_parameterized_closed_form.
by smt().
qed.

lemma A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_parameterized_shadow_semantic_post_marginal x s)
      (d_le_parameterized_post_fs_semantic_programmed_view x s)
      <= le_fs_parameterized_local_bad_branch_mass.
proof.
move=> x s.
rewrite (d_le_fs_parameterized_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite (d_le_parameterized_post_fs_semantic_programmed_view_pairE x s).
pose dpre := d_le_parameterized_pre_fs_semantic_programming_view x s.
pose F := fun (p : le_transcript_observable * bool) =>
  LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
    (fst p) (snd p).
have Hmap :
  sdist (dmap (dpre `*` d_le_fs_parameterized_shadow_branch_choice) F)
        (dmap (dpre `*` dunit false) F)
    <= sdist (dpre `*` d_le_fs_parameterized_shadow_branch_choice)
         (dpre `*` dunit false).
  exact (sdist_dmap (dpre `*` d_le_fs_parameterized_shadow_branch_choice)
    (dpre `*` dunit false) F).
have Hdprod :
  sdist (dpre `*` d_le_fs_parameterized_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist dpre dpre +
       sdist d_le_fs_parameterized_shadow_branch_choice (dunit false).
  exact (sdist_dprod dpre dpre d_le_fs_parameterized_shadow_branch_choice
    (dunit false)).
have Hdprod' :
  sdist (dpre `*` d_le_fs_parameterized_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist d_le_fs_parameterized_shadow_branch_choice (dunit false).
  have Hsame : sdist dpre dpre <= 0%r.
    by rewrite sdistdd.
  have Hsum :
    sdist dpre dpre +
    sdist d_le_fs_parameterized_shadow_branch_choice (dunit false) <=
    0%r + sdist d_le_fs_parameterized_shadow_branch_choice (dunit false).
    apply (ler_add _ _ _ _ Hsame).
    by [].
  have Hstep :
    sdist (dpre `*` d_le_fs_parameterized_shadow_branch_choice)
          (dpre `*` dunit false) <=
    0%r + sdist d_le_fs_parameterized_shadow_branch_choice (dunit false).
    exact (ler_trans _ _ _ Hdprod Hsum).
  by smt().
apply (ler_trans _ _ _ Hmap).
apply (ler_trans _ _ _ Hdprod').
exact le_fs_parameterized_shadow_branch_choice_sdist_dunit_false_le_bad_branch_mass.
qed.

lemma A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_parameterized_budget :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_parameterized_shadow_semantic_post_marginal x s)
      (d_le_parameterized_post_fs_semantic_programmed_view x s)
      <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s.
have Hmass :=
  A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_bad_branch_mass x s.
exact (ler_trans _ _ _ Hmass
  le_fs_parameterized_local_bad_branch_mass_le_epsilon_le_fs_parameterized).
qed.