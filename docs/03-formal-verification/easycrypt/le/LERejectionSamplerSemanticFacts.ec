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

lemma le_rejection_shadow_semantic_reject_event_of_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_rejection_shadow_reject_event
    (le_rejection_shadow_semantic_state_of_branch_execution x s obs
      (LERealExecution.le_real_execution_semantic_rejection_decision_reject
        (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
          category))) =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite (le_rejection_shadow_semantic_reject_event_branch_stateE x s obs
  (LERealExecution.le_real_execution_semantic_rejection_decision_reject
    (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
      category))).
exact
  (LERealExecution.le_real_execution_semantic_rejection_decision_of_category_rejectE
    category).
qed.

lemma le_rejection_shadow_semantic_accept_event_of_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_rejection_shadow_accept_event
    (le_rejection_shadow_semantic_state_of_branch_execution x s obs
      (LERealExecution.le_real_execution_semantic_rejection_decision_reject
        (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
          category))) =
  ! BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite /le_rejection_shadow_accept_event.
rewrite /le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
rewrite (LERealExecution.le_real_execution_semantic_rejection_decision_of_category_rejectE
  category).
by case (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category).
qed.

lemma le_rejection_shadow_semantic_post_observable_of_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  (le_rejection_shadow_semantic_state_of_branch_execution x s obs
    (LERealExecution.le_real_execution_semantic_rejection_decision_reject
      (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
        category))).`lers_post_observable =
  le_rejection_shadow_semantic_branch_image_of_observable x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category).
proof.
rewrite (le_rejection_shadow_semantic_post_branch_imageE x s obs
  (LERealExecution.le_real_execution_semantic_rejection_decision_reject
    (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
      category))).
by rewrite
  (LERealExecution.le_real_execution_semantic_rejection_decision_of_category_rejectE
    category).
qed.

lemma le_rejection_shadow_semantic_post_observable_of_accept_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_rejection_shadow_semantic_state_of_branch_execution x s obs
    (LERealExecution.le_real_execution_semantic_rejection_decision_reject
      (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
        BudgetParameters.LERejectionSemanticTicketAccept))).`lers_post_observable =
  obs.
proof.
rewrite (le_rejection_shadow_semantic_post_observable_of_categoryE x s obs
  BudgetParameters.LERejectionSemanticTicketAccept).
rewrite /le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
exact (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id x s obs).
qed.

lemma le_rejection_shadow_semantic_hidden_branch_bit_of_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  (le_rejection_shadow_semantic_state_of_branch_execution x s obs
    (LERealExecution.le_real_execution_semantic_rejection_decision_reject
      (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
        category))).`lers_hidden_material.`lershm_challenge_seed_material.`lerecsm_branch =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite /le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
exact
  (LERealExecution.le_real_execution_semantic_rejection_decision_of_category_rejectE
    category).
qed.

lemma le_rejection_shadow_semantic_branch_state_has_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  obs \in d_le_rejection_real_execution_view x s =>
  reject \in d_le_rejection_shadow_semantic_branch_choice =>
  le_rejection_shadow_semantic_state_of_branch_execution x s obs reject
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
move=> Hobs Hreject.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite supp_dmap.
exists (obs, reject); split.
  by rewrite supp_dprod Hobs Hreject.
by [].
qed.

lemma le_rejection_shadow_semantic_accept_branch_support
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_state_of_branch_execution x s
    (le_real_execution_observable x s) false
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
apply (le_rejection_shadow_semantic_branch_state_has_support x s
  (le_real_execution_observable x s) false).
  exact (le_real_execution_observable_in_rejection_execution_view x s).
exact le_rejection_shadow_semantic_accept_branch_has_support.
qed.

lemma le_rejection_shadow_semantic_reject_branch_support
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_state_of_branch_execution x s
    (le_real_execution_observable x s) true
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
apply (le_rejection_shadow_semantic_branch_state_has_support x s
  (le_real_execution_observable x s) true).
  exact (le_real_execution_observable_in_rejection_execution_view x s).
exact le_rejection_shadow_semantic_reject_branch_has_support.
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_matches_real_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s = d_le_real_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view.
by rewrite /d_le_rejection_real_execution_view
  /LERejectionSamplerCore.d_le_rejection_real_execution_view.
qed.