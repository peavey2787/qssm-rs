require import QssmTypes.
require import AllCore Distr.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LESurface.
require import LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require import LEFsProgrammingCoupledState.
require import LEFsProgrammingMarginalHelpers.
require import LEFsProgrammingMarginalStateFacts.
require import LEFsProgrammingPostMarginal.
require BudgetParameters.
(*---*) import RealOrder.
op d_le_pre_fs_programming_view (x : qssm_public_input) (s : seed) : le_transcript_observable distr = LEFsProgrammingCoreDefs.d_le_pre_fs_programming_view x s.
op d_le_pre_fs_semantic_programming_view (x : qssm_public_input) (s : seed) : le_transcript_observable distr = LEFsProgrammingCoreDefs.d_le_pre_fs_semantic_programming_view x s.
op d_le_fs_shadow_branch_choice : bool distr = LEFsProgrammingShadowBranch.d_le_fs_shadow_branch_choice.
op le_fs_shadow_local_bad_branch_mass : real = LEFsProgrammingShadowBranch.le_fs_shadow_local_bad_branch_mass.
op d_le_fs_shadow_coupled_state (x : qssm_public_input) (s : seed) = LEFsProgrammingCoupledState.d_le_fs_shadow_coupled_state x s.
op d_le_fs_shadow_semantic_coupled_state (x : qssm_public_input) (s : seed) = LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_coupled_state x s.
op d_le_fs_shadow_pre_marginal (x : qssm_public_input) (s : seed) = LEFsProgrammingCoupledState.d_le_fs_shadow_pre_marginal x s.
op d_le_fs_shadow_post_marginal (x : qssm_public_input) (s : seed) = LEFsProgrammingCoupledState.d_le_fs_shadow_post_marginal x s.
op le_fs_shadow_bad_event = LEFsProgrammingShadowBranch.le_fs_shadow_bad_event.
op le_fs_shadow_semantic_bad_event = LEFsProgrammingShadowBranch.le_fs_shadow_semantic_bad_event.
op le_fs_shadow_failure_probability (x : qssm_public_input) (s : seed) = mu (dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_bad_event) (fun (bad : bool) => bad).
op le_fs_shadow_semantic_failure_probability (x : qssm_public_input) (s : seed) = mu (dmap (d_le_fs_shadow_semantic_coupled_state x s) le_fs_shadow_semantic_bad_event) (fun (bad : bool) => bad).
lemma le_fs_shadow_branch_choice_mass_false :
  mu1 d_le_fs_shadow_branch_choice false =
  (BudgetParameters.total_slot_count - BudgetParameters.bad_slot_count)%r / BudgetParameters.total_slot_count%r.
proof. rewrite /d_le_fs_shadow_branch_choice. exact BudgetParameters.le_fs_semantic_branch_choice_mass_false. qed.
lemma le_fs_shadow_branch_choice_mass_true :
  mu1 d_le_fs_shadow_branch_choice true = BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof. rewrite /d_le_fs_shadow_branch_choice. exact BudgetParameters.le_fs_semantic_branch_choice_mass_true. qed.
lemma le_fs_shadow_local_bad_branch_mass_is_true_mass :
  le_fs_shadow_local_bad_branch_mass = mu1 d_le_fs_shadow_branch_choice true.
proof. rewrite /le_fs_shadow_local_bad_branch_mass; apply/mu_eq=> bad /=; by case: bad. qed.
lemma le_fs_shadow_local_bad_branch_mass_closed_form :
  le_fs_shadow_local_bad_branch_mass = BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof. rewrite le_fs_shadow_local_bad_branch_mass_is_true_mass. exact le_fs_shadow_branch_choice_mass_true. qed.
lemma le_fs_shadow_local_bad_branch_mass_eq_epsilon_le_fs_semantic :
  le_fs_shadow_local_bad_branch_mass = BudgetParameters.epsilon_le_fs_semantic.
proof. rewrite le_fs_shadow_local_bad_branch_mass_is_true_mass /d_le_fs_shadow_branch_choice /BudgetParameters.epsilon_le_fs_semantic. by []. qed.
lemma le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic :
  le_fs_shadow_local_bad_branch_mass <= BudgetParameters.epsilon_le_fs_semantic.
proof. rewrite le_fs_shadow_local_bad_branch_mass_eq_epsilon_le_fs_semantic. by []. qed.
lemma le_fs_shadow_local_bad_branch_mass_nonneg :
  0%r <= le_fs_shadow_local_bad_branch_mass.
proof.
rewrite /le_fs_shadow_local_bad_branch_mass.
have Hsub : mu d_le_fs_shadow_branch_choice (fun (bad : bool) => ! bad) <= mu d_le_fs_shadow_branch_choice predT.
  apply mu_sub => bad /=. by case: bad.
have Hnot : mu d_le_fs_shadow_branch_choice (fun (bad : bool) => ! bad) =
  mu d_le_fs_shadow_branch_choice predT - mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad)
  by rewrite mu_not /weight.
move: Hsub. rewrite Hnot. by smt().
qed.
lemma le_real_execution_observable_in_pre_fs_programming_view (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_pre_fs_programming_view x s.
proof.
have -> : d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
  rewrite /d_le_pre_fs_programming_view. exact (LEFsProgrammingMarginalHelpers.d_le_pre_fs_programming_view_dunit x s).
by rewrite supp_dunit.
qed.
lemma d_le_fs_shadow_bad_event_image_zero :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_bad_event = dunit false.
proof.
move=> x s.
have -> : d_le_fs_shadow_coupled_state x s =
    dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
      (fun (p : le_transcript_observable * bool) => le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
  rewrite /d_le_fs_shadow_coupled_state /d_le_pre_fs_programming_view /d_le_fs_shadow_branch_choice.
  exact (LEFsProgrammingMarginalHelpers.d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) => le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_bad_event ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_bad_event \o (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) => false).
  apply eq_dmap_in=> p _ /=. case: p=> obs bad /=. rewrite /(\o).
  have -> : le_fs_shadow_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = false.
    exact (LEFsProgrammingMarginalStateFacts.le_fs_shadow_bad_event_branch_stateE obs bad).
  by [].
rewrite Hmap.
rewrite -(dmap_comp fst (fun (_ : le_transcript_observable) => false)
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hll_branch : is_lossless d_le_fs_shadow_branch_choice.
  rewrite /d_le_fs_shadow_branch_choice. exact BudgetParameters.le_fs_semantic_branch_choice_lossless.
rewrite (le_fs_shadow_dmap_dprod_fst_lossless (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice Hll_branch).
have -> : d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
  rewrite /d_le_pre_fs_programming_view. exact (LEFsProgrammingMarginalHelpers.d_le_pre_fs_programming_view_dunit x s).
by rewrite dmap_dunit.
qed.
lemma le_fs_shadow_failure_probability_zero :
  forall (x : qssm_public_input) (s : seed), le_fs_shadow_failure_probability x s = 0%r.
proof. move=> x s; rewrite /le_fs_shadow_failure_probability (d_le_fs_shadow_bad_event_image_zero x s). by rewrite dunitE /=. qed.
lemma d_le_fs_shadow_semantic_bad_event_image_branch_choice :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_fs_shadow_semantic_coupled_state x s) le_fs_shadow_semantic_bad_event = d_le_fs_shadow_branch_choice.
proof.
move=> x s.
have -> : d_le_fs_shadow_semantic_coupled_state x s =
    dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
      (fun (p : le_transcript_observable * bool) => le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
  rewrite /d_le_fs_shadow_semantic_coupled_state /d_le_pre_fs_semantic_programming_view /d_le_fs_shadow_branch_choice.
  exact (LEFsProgrammingMarginalHelpers.d_le_fs_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) => le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_semantic_bad_event ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_semantic_bad_event \o (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice) snd.
  apply eq_dmap_in=> p _ /=. case: p=> obs bad /=. rewrite /(\o).
  have -> : le_fs_shadow_semantic_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = bad.
    exact (LEFsProgrammingMarginalStateFacts.le_fs_shadow_semantic_bad_event_branch_stateE obs bad).
  by [].
rewrite Hmap.
have Hll : is_lossless (d_le_pre_fs_semantic_programming_view x s).
  rewrite /d_le_pre_fs_semantic_programming_view. exact (LEFsProgrammingMarginalHelpers.d_le_pre_fs_semantic_programming_view_lossless x s).
exact (le_fs_shadow_dmap_dprod_snd_lossless (d_le_pre_fs_semantic_programming_view x s) d_le_fs_shadow_branch_choice Hll).
qed.
lemma le_fs_shadow_semantic_failure_probability_exact_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_semantic_failure_probability x s = le_fs_shadow_local_bad_branch_mass.
proof. move=> x s; rewrite /le_fs_shadow_semantic_failure_probability /le_fs_shadow_local_bad_branch_mass (d_le_fs_shadow_semantic_bad_event_image_branch_choice x s). by []. qed.
lemma le_fs_shadow_semantic_failure_probability_closed_form :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_semantic_failure_probability x s = BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof. move=> x s; rewrite le_fs_shadow_semantic_failure_probability_exact_branch_mass. exact le_fs_shadow_local_bad_branch_mass_closed_form. qed.
lemma A_LE_fs_shadow_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_pre_marginal x s) (d_le_fs_shadow_post_marginal x s) <= le_fs_shadow_failure_probability x s.
proof.
move=> x s.
have -> : d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
  rewrite /d_le_fs_shadow_pre_marginal /d_le_fs_shadow_post_marginal.
  exact (LEFsProgrammingPostMarginal.d_le_fs_shadow_pre_post_marginals_equal x s).
rewrite sdistdd (le_fs_shadow_failure_probability_zero x s). by [].
qed.
lemma A_LE_fs_shadow_sdist_le_semantic_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_pre_marginal x s) (d_le_fs_shadow_post_marginal x s) <= le_fs_shadow_semantic_failure_probability x s.
proof.
move=> x s.
have -> : d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
  rewrite /d_le_fs_shadow_pre_marginal /d_le_fs_shadow_post_marginal.
  exact (LEFsProgrammingPostMarginal.d_le_fs_shadow_pre_post_marginals_equal x s).
rewrite sdistdd (le_fs_shadow_semantic_failure_probability_exact_branch_mass x s) /le_fs_shadow_local_bad_branch_mass. by [].
qed.
lemma A_LE_fs_shadow_failure_probability_le_budget :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_failure_probability x s <= BudgetParameters.epsilon_le_fs.
proof. move=> x s; rewrite (le_fs_shadow_failure_probability_zero x s) /BudgetParameters.epsilon_le_fs. by []. qed.