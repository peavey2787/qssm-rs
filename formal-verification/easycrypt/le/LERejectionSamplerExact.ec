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

(* Exact-zero current-model lane below the facade. *)

lemma le_rejection_shadow_accepts_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_rejection_shadow_state_of_execution x s obs).`lers_accepts = true.
proof.
rewrite /le_rejection_shadow_state_of_execution.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_rejection_shadow_hidden_material_of_execution.
by rewrite /le_real_execution_challenge_seed_material_of /=.
qed.

lemma le_rejection_shadow_post_of_execution_matches_transform
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_rejection_shadow_state_of_execution x s obs).`lers_post_observable =
  le_rejection_transform obs.
proof.
rewrite /le_rejection_shadow_state_of_execution.
rewrite /le_rejection_shadow_post_of_execution.
rewrite /le_rejection_shadow_hidden_material_of_execution.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_real_execution_challenge_seed_material_of /=.
by rewrite /le_rejection_transform /le_post_rejection_surrogate.
qed.

lemma le_rejection_shadow_reject_event_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  le_rejection_shadow_reject_event (le_rejection_shadow_state_of_execution x s obs) = false.
proof.
rewrite /le_rejection_shadow_reject_event.
by rewrite (le_rejection_shadow_accepts_current_model x s obs).
qed.

lemma d_le_rejection_shadow_pre_marginal_matches_execution_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_rejection_real_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_shadow_pre_marginal /LERejectionSamplerCore.d_le_rejection_shadow_pre_marginal.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_coupled_state.
rewrite (dmap_comp (LERejectionSamplerCore.le_rejection_shadow_state_of_execution x s)
  LERejectionSamplerCore.le_rejection_shadow_pre_observable
  (d_le_rejection_real_execution_view x s)).
have Hmap :
  dmap (d_le_rejection_real_execution_view x s)
    (LERejectionSamplerCore.le_rejection_shadow_pre_observable \o
      (LERejectionSamplerCore.le_rejection_shadow_state_of_execution x s)) =
  dmap (d_le_rejection_real_execution_view x s)
    (fun (obs : le_transcript_observable) => obs).
- apply eq_dmap_in=> obs _ /=.
  by rewrite /LERejectionSamplerCore.le_rejection_shadow_pre_observable
    /LERejectionSamplerCore.le_rejection_shadow_state_of_execution /(\o).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma d_le_rejection_shadow_post_marginal_matches_execution_transform :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_post_marginal x s = d_le_rejection_post_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_shadow_post_marginal /LERejectionSamplerCore.d_le_rejection_shadow_post_marginal.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_coupled_state.
rewrite (dmap_comp (LERejectionSamplerCore.le_rejection_shadow_state_of_execution x s)
  LERejectionSamplerCore.le_rejection_shadow_post_observable
  (d_le_rejection_real_execution_view x s)).
have Hmap :
  dmap (d_le_rejection_real_execution_view x s)
    (LERejectionSamplerCore.le_rejection_shadow_post_observable \o
      (LERejectionSamplerCore.le_rejection_shadow_state_of_execution x s)) =
  dmap (d_le_rejection_real_execution_view x s)
    le_rejection_transform.
- apply eq_dmap_in=> obs _ /=.
  rewrite /LERejectionSamplerCore.le_rejection_shadow_post_observable /(\o).
  exact (le_rejection_shadow_post_of_execution_matches_transform x s obs).
rewrite Hmap.
by rewrite /d_le_rejection_post_execution_view.
qed.

lemma d_le_rejection_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_rejection_shadow_post_marginal x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_pre_marginal_matches_execution_view.
rewrite d_le_rejection_shadow_post_marginal_matches_execution_transform.
by rewrite /d_le_rejection_post_execution_view /d_le_rejection_real_execution_view
  /LERejectionSamplerCore.d_le_rejection_post_execution_view
  /LERejectionSamplerCore.d_le_rejection_real_execution_view
  /le_rejection_transform /LERejectionSamplerCore.le_rejection_transform
  /le_post_rejection_surrogate dmap_id.
qed.

lemma le_rejection_shadow_failure_probability_zero :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_failure_probability x s = 0%r.
proof.
move=> x s.
rewrite /le_rejection_shadow_failure_probability.
rewrite /LERejectionSamplerCore.le_rejection_shadow_failure_probability.
rewrite /LERejectionSamplerCore.d_le_rejection_shadow_coupled_state.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit dunitE /=.
rewrite /le_rejection_shadow_reject_event.
rewrite /LERejectionSamplerCore.le_rejection_shadow_reject_event.
rewrite /LERejectionSamplerCore.le_rejection_shadow_state_of_execution.
rewrite /LERejectionSamplerCore.le_rejection_shadow_accepts_from_hidden_material.
rewrite /LERejectionSamplerCore.le_rejection_shadow_hidden_material_of_execution.
rewrite /le_real_execution_challenge_seed_material_of /=.
by [].
qed.

lemma A_LE_rejection_shadow_failure_probability_le_semantic_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_failure_probability x s <= BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_failure_probability_zero x s).
rewrite /BudgetParameters.epsilon_le_rej_semantic.
by [].
qed.

lemma le_real_view_matches_rejection_execution :
  forall (x : qssm_public_input) (s : seed),
    d_le_real_view x s = d_le_rejection_real_execution_view x s.
proof.
by move=> x s; rewrite /d_le_rejection_real_execution_view
  /LERejectionSamplerCore.d_le_rejection_real_execution_view.
qed.

lemma d_le_rejection_shadow_pre_marginal_matches_real_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_real_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_pre_marginal_matches_execution_view.
exact (le_real_view_matches_rejection_execution x s).
qed.

lemma le_post_rejection_view_matches_execution_transform :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_rejection_view x s = d_le_rejection_post_execution_view x s.
proof.
move=> x s.
rewrite /d_le_post_rejection_view /d_le_rejection_post_execution_view.
rewrite /LERejectionSamplerCore.d_le_rejection_post_execution_view.
rewrite /d_le_rejection_real_execution_view /LERejectionSamplerCore.d_le_rejection_real_execution_view.
rewrite /le_rejection_transform /LERejectionSamplerCore.le_rejection_transform.
by [].
qed.

lemma d_le_rejection_shadow_post_marginal_matches_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_post_marginal x s = d_le_post_rejection_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_post_marginal_matches_execution_transform.
by rewrite -(le_post_rejection_view_matches_execution_transform x s).
qed.