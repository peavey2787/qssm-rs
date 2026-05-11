require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LERejectionSampler.
require import LESurface.
require import LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require import LEFsProgrammingCoupledState.
require import LEFsProgrammingMarginalHelpers.
require import LEFsProgrammingMarginals.
require BudgetParameters.

(*---*) import RealOrder.

lemma le_fs_post_marginal_branch_choice_mass_false :
  mu1 d_le_fs_shadow_branch_choice false =
  (BudgetParameters.total_slot_count - BudgetParameters.bad_slot_count)%r /
  BudgetParameters.total_slot_count%r.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_mass_false.
qed.

lemma le_fs_post_marginal_branch_choice_mass_true :
  mu1 d_le_fs_shadow_branch_choice true =
  BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_mass_true.
qed.

lemma le_fs_post_marginal_local_bad_branch_mass_is_true_mass :
  le_fs_shadow_local_bad_branch_mass = mu1 d_le_fs_shadow_branch_choice true.
proof.
rewrite /le_fs_shadow_local_bad_branch_mass.
have Hmu1 : mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad) =
    mu1 d_le_fs_shadow_branch_choice true.
  apply/mu_eq=> bad /=.
  by case: bad.
exact Hmu1.
qed.

lemma le_fs_post_marginal_local_bad_branch_mass_closed_form :
  le_fs_shadow_local_bad_branch_mass =
  BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof.
rewrite le_fs_post_marginal_local_bad_branch_mass_is_true_mass.
exact le_fs_post_marginal_branch_choice_mass_true.
qed.

lemma d_le_fs_shadow_post_marginal_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_post_fs_programmed_view x s.
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_post_marginal_matches_programmed_view.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_bad_branch_image x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit true)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_bad_branch_image_pairE.
qed.

lemma d_le_fs_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_pre_post_marginals_equal.
qed.

lemma le_fs_surrogate_transform_id
  (obs : le_transcript_observable) :
  le_fs_surrogate_transform obs = obs.
proof.
exact (LEFsProgrammingMarginals.le_fs_surrogate_transform_id obs).
qed.

lemma d_le_fs_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_fs_shadow_state_of_branch_observable (fst p) (snd p)).`lefss_semantic_post_observable).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_post_marginal_pairE.
qed.

lemma d_le_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_semantic_programmed_view x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit false)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_post_fs_semantic_programmed_view_pairE.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_post_marginal_branch_split_pairE.
qed.

lemma le_fs_shadow_branch_choice_sdist_dunit_false_le_bad_branch_mass :
  sdist d_le_fs_shadow_branch_choice (dunit false) <=
  le_fs_shadow_local_bad_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE : mu d_le_fs_shadow_branch_choice E = mu d_le_fs_shadow_branch_choice predT.
      apply/mu_eq=> bad /=.
      by case: bad=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_fs_shadow_branch_choice = 1%r.
      exact (is_losslessP _ le_fs_marginals_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE : mu d_le_fs_shadow_branch_choice E = mu1 d_le_fs_shadow_branch_choice false.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE le_fs_post_marginal_branch_choice_mass_false.
  rewrite le_fs_post_marginal_local_bad_branch_mass_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE : mu d_le_fs_shadow_branch_choice E = mu1 d_le_fs_shadow_branch_choice true.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE le_fs_post_marginal_branch_choice_mass_true.
  rewrite le_fs_post_marginal_local_bad_branch_mass_closed_form.
  by smt().
have HE : mu d_le_fs_shadow_branch_choice E = mu d_le_fs_shadow_branch_choice pred0.
  apply/mu_eq=> bad /=.
  by case: bad=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_fs_post_marginal_local_bad_branch_mass_closed_form.
by smt().
qed.

lemma le_fs_shadow_branch_choice_sdist_dunit_falseE :
  sdist d_le_fs_shadow_branch_choice (dunit false) =
  le_fs_shadow_local_bad_branch_mass.
proof.
apply ler_anti.
have Hlb :
    `|mu d_le_fs_shadow_branch_choice (pred1 true) -
      mu (dunit false) (pred1 true)| <=
    sdist d_le_fs_shadow_branch_choice (dunit false).
  exact (sdist_upper_bound d_le_fs_shadow_branch_choice (dunit false) (pred1 true)).
move: Hlb.
rewrite (dunitE (pred1 true) false) /=.
move=> Hlb.
have Habs : le_fs_shadow_local_bad_branch_mass =
    `|mu d_le_fs_shadow_branch_choice (pred1 true) - 0%r|.
  have Hnonneg : 0%r <= mu d_le_fs_shadow_branch_choice (pred1 true).
    exact (ge0_mu1 d_le_fs_shadow_branch_choice true).
  have Hmass : le_fs_shadow_local_bad_branch_mass =
      mu d_le_fs_shadow_branch_choice (pred1 true).
    exact le_fs_post_marginal_local_bad_branch_mass_is_true_mass.
  smt().
by smt().
qed.

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_branch_choice_distance :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_semantic_programmed_view x s)
      <= sdist d_le_fs_shadow_branch_choice (dunit false).
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite (d_le_post_fs_semantic_programmed_view_pairE x s).
pose dpre := d_le_pre_fs_semantic_programming_view x s.
pose F := fun (p : le_transcript_observable * bool) =>
  le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p).
have Hmap :
  sdist (dmap (dpre `*` d_le_fs_shadow_branch_choice) F)
        (dmap (dpre `*` dunit false) F)
    <= sdist (dpre `*` d_le_fs_shadow_branch_choice)
         (dpre `*` dunit false).
  exact (sdist_dmap (dpre `*` d_le_fs_shadow_branch_choice)
    (dpre `*` dunit false) F).
have Hdprod :
  sdist (dpre `*` d_le_fs_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist dpre dpre + sdist d_le_fs_shadow_branch_choice (dunit false).
  exact (sdist_dprod dpre dpre d_le_fs_shadow_branch_choice (dunit false)).
have Hdprod' :
  sdist (dpre `*` d_le_fs_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist d_le_fs_shadow_branch_choice (dunit false).
  have Hsame : sdist dpre dpre <= 0%r.
    by rewrite sdistdd.
  have Hsum :
    sdist dpre dpre + sdist d_le_fs_shadow_branch_choice (dunit false) <=
    0%r + sdist d_le_fs_shadow_branch_choice (dunit false).
    apply (ler_add _ _ _ _ Hsame).
    by [].
  have Hstep :
    sdist (dpre `*` d_le_fs_shadow_branch_choice)
          (dpre `*` dunit false) <=
    0%r + sdist d_le_fs_shadow_branch_choice (dunit false).
    exact (ler_trans _ _ _ Hdprod Hsum).
  by smt().
apply (ler_trans _ _ _ Hmap).
exact (ler_trans _ _ _ Hdprod').
qed.

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_semantic_programmed_view x s)
      <= le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s.
have Hdist := A_LE_fs_shadow_semantic_post_marginal_sdist_le_branch_choice_distance x s.
rewrite le_fs_shadow_branch_choice_sdist_dunit_falseE in Hdist.
exact Hdist.
qed.
