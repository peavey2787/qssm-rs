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
require import LEFsProgrammingMarginalStateFacts.
require BudgetParameters.

(*---*) import RealOrder.

lemma le_fs_shadow_bad_event_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
move=> _.
exact (le_fs_shadow_bad_event_stateE obs).
qed.

lemma d_le_fs_shadow_pre_marginal_matches_pre_programming_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_pre_fs_programming_view x s.
proof.
move=> x s.
rewrite /d_le_fs_shadow_pre_marginal.
rewrite /d_le_fs_shadow_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_pre_observable
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /le_fs_shadow_pre_observable /le_fs_shadow_state_of_branch_observable /(\o).
rewrite Hmap.
exact (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_marginals_branch_choice_lossless).
qed.

lemma d_le_fs_shadow_pre_marginal_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_pre_marginal x s =>
  obs = le_real_execution_observable x s.
proof.
move=> Hobs.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view in Hobs.
exact (d_le_pre_fs_programming_view_supportE x s obs Hobs).
qed.

lemma le_fs_shadow_good_event_on_pre_marginal_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_pre_marginal x s =>
  le_fs_shadow_good_event x s obs.
proof.
move=> Hobs.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view in Hobs.
exact (le_fs_shadow_good_event_on_pre_programming_support x s obs Hobs).
qed.

lemma d_le_fs_shadow_pre_marginal_matches_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_post_rejection_view x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view.
by rewrite /d_le_pre_fs_programming_view.
qed.

lemma d_le_fs_shadow_semantic_pre_marginal_matches_pre_semantic_programming_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_pre_marginal x s = d_le_pre_fs_semantic_programming_view x s.
proof.
move=> x s.
rewrite /d_le_fs_shadow_semantic_pre_marginal.
rewrite /d_le_fs_shadow_semantic_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_pre_observable
  ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /le_fs_shadow_pre_observable /le_fs_shadow_state_of_branch_observable /(\o).
rewrite Hmap.
exact (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_semantic_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_marginals_branch_choice_lossless).
qed.

lemma d_le_fs_shadow_semantic_pre_marginal_matches_semantic_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_pre_marginal x s =
    LERejectionSampler.d_le_semantic_post_rejection_view x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_semantic_pre_marginal_matches_pre_semantic_programming_view.
by rewrite /d_le_pre_fs_semantic_programming_view.
qed.
