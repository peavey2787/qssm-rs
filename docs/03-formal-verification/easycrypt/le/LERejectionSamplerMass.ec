require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LERealExecution.
require import LERejectionSamplerCore.
require BudgetParameters.

(*---*) import RealOrder.

op d_le_semantic_post_rejection_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_rejection_shadow_semantic_post_marginal x s.

op le_rejection_shadow_semantic_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_rejection_shadow_semantic_coupled_state x s)
       le_rejection_shadow_reject_event)
    (fun (reject : bool) => reject).

op le_rejection_shadow_semantic_ticket_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability x s.

lemma le_rejection_shadow_semantic_post_branch_imageE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  (le_rejection_shadow_semantic_state_of_branch_execution x s obs reject).`lers_post_observable =
  le_rejection_shadow_semantic_branch_image_of_observable x s obs reject.
proof.
case: reject=> /=.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_post_of_execution.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch /=.
  by [].
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
case: qmat=> rowseed rowdig respdig log badflag /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution.
rewrite /LERejectionSamplerCore.le_rejection_shadow_post_of_execution.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch.
rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_primitive_material_of_observable_ticket /=.
rewrite /LERealExecution.le_real_execution_challenge_seed_obs_of_material.
rewrite /LERealExecution.le_real_execution_programmed_query_digest_obs_of_material.
rewrite /LERealExecution.le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_obs_of_branch.
rewrite /LERealExecution.le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch /=.
by [].
qed.

lemma le_rejection_shadow_semantic_reject_event_branch_stateE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  le_rejection_shadow_reject_event
    (le_rejection_shadow_semantic_state_of_branch_execution x s obs reject) = reject.
proof.
case: reject.
  rewrite /le_rejection_shadow_reject_event.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution /=.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
  by [].
rewrite /le_rejection_shadow_reject_event.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
by [].
qed.

lemma d_le_rejection_shadow_semantic_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_coupled_state x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p)).
proof.
by move=> x s; rewrite /LERejectionSamplerCore.d_le_rejection_shadow_semantic_coupled_state.
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s =
    d_le_rejection_real_execution_view x s.
proof.
move=> x s.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_semantic_pre_marginal.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_semantic_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  LERejectionSamplerCore.le_rejection_shadow_pre_observable
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (LERejectionSamplerCore.le_rejection_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /LERejectionSamplerCore.le_rejection_shadow_pre_observable /(\o)
    /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution.
rewrite Hmap.
exact (LERejectionSamplerCore.le_rejection_shadow_dmap_dprod_fst_lossless
  (d_le_rejection_real_execution_view x s)
  d_le_rejection_shadow_semantic_branch_choice
  le_rejection_shadow_semantic_branch_choice_lossless).
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p)).`lers_post_observable).
proof.
move=> x s.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_semantic_post_marginal.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_semantic_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  LERejectionSamplerCore.le_rejection_shadow_post_observable
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
by rewrite /LERejectionSamplerCore.le_rejection_shadow_post_observable /(\o).
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_rejection_shadow_semantic_branch_image_of_observable x s (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_post_marginal_pairE x s).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
exact (le_rejection_shadow_semantic_post_branch_imageE x s obs reject).
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s =
      dmap (dunit false)
        (fun reject =>
          le_rejection_shadow_semantic_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id
  x s (le_real_execution_observable x s)).
by [].
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap d_le_rejection_shadow_semantic_branch_choice
        (fun reject =>
          le_rejection_shadow_semantic_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
have Hmap :
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_shadow_semantic_branch_image_of_observable x s (fst p) (snd p)) =
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_shadow_semantic_branch_image_of_observable x s
        (le_real_execution_observable x s) (snd p)).
  apply eq_dmap_in=> p Hp /=.
  case: p Hp=> obs reject /=.
  rewrite supp_dprod => -[Hobs _].
  move: Hobs; rewrite supp_dunit => ->.
  by [].
rewrite Hmap.
rewrite -(dmap_comp snd
  (fun reject =>
    le_rejection_shadow_semantic_branch_image_of_observable x s
      (le_real_execution_observable x s) reject)
  ((dunit (le_real_execution_observable x s)) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
rewrite (LERejectionSamplerCore.le_rejection_shadow_dmap_dprod_snd_lossless
  (dunit (le_real_execution_observable x s))
  d_le_rejection_shadow_semantic_branch_choice
  (dunit_ll (le_real_execution_observable x s))).
by [].
qed.

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

lemma d_le_rejection_shadow_semantic_reject_event_image_branch_choice :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_rejection_shadow_semantic_coupled_state x s)
      le_rejection_shadow_reject_event =
      d_le_rejection_shadow_semantic_branch_choice.
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  le_rejection_shadow_reject_event
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (le_rejection_shadow_reject_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice) snd.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /(\o) (le_rejection_shadow_semantic_reject_event_branch_stateE x s obs reject).
rewrite Hmap.
exact (LERejectionSamplerCore.le_rejection_shadow_dmap_dprod_snd_lossless
  (d_le_rejection_real_execution_view x s)
  d_le_rejection_shadow_semantic_branch_choice
  (LERejectionSamplerCore.d_le_rejection_real_execution_view_lossless x s)).
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