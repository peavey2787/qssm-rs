require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require BudgetParameters.

(*---*) import RealOrder.

lemma le_fs_shadow_semantic_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_semantic_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = bad.
proof.
rewrite /le_fs_shadow_semantic_bad_event /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_post_of_observable /=.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_shadow_pre_query_material_of_observable /=.
case: bad => /=.
- rewrite /le_fs_shadow_semantic_post_observable /=.
  by rewrite /le_fs_query_material_obs /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by rewrite /le_fs_program_query_material.
qed.

lemma le_fs_shadow_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = false.
proof.
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
case: qmat=> rowseed rowdig respdig log badflag /=.
rewrite /le_fs_shadow_bad_event /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable /=.
rewrite /le_fs_query_material_obs /=.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate /le_fs_program_query_material /=.
by smt().
qed.

lemma le_fs_shadow_bad_event_stateE
  (obs : le_transcript_observable) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
rewrite /le_fs_shadow_state_of_observable.
exact (le_fs_shadow_bad_event_branch_stateE obs
  ((le_fs_query_material_obs obs).`leqm_bad_flag)).
qed.

lemma le_fs_shadow_post_of_observable_matches_surrogate
  (obs : le_transcript_observable) :
  ! (le_fs_query_material_obs obs).`leqm_bad_flag =>
  (le_fs_shadow_state_of_observable obs).`lefss_post_observable =
  le_fs_surrogate_transform obs.
proof.
move=> _.
rewrite /le_fs_shadow_state_of_observable /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
by [].
qed.

lemma le_fs_shadow_semantic_post_observable_preserves_visible_fields
  (obs : le_transcript_observable) :
  le_commitment_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_commitment_coeffs obs /\
  le_t_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_t_coeffs obs /\
  le_z_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_z_coeffs obs /\
  le_challenge_seed_obs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_challenge_seed_obs obs /\
  le_programmed_query_digest_obs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_programmed_query_digest_obs obs.
proof.
rewrite /le_fs_shadow_semantic_post_observable.
  rewrite /le_fs_shadow_hidden_material_of_observable.
  rewrite /le_fs_shadow_hidden_material_of_observable_branch /=.
rewrite /le_fs_programmed_response_of_observable /=.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by [].
qed.

lemma le_fs_shadow_post_observable_preserves_visible_fields
  (obs : le_transcript_observable) :
  le_commitment_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_commitment_coeffs obs /\
  le_t_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_t_coeffs obs /\
  le_z_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_z_coeffs obs /\
  le_challenge_seed_obs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_challenge_seed_obs obs /\
  le_programmed_query_digest_obs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_programmed_query_digest_obs obs.
proof.
rewrite /le_fs_shadow_state_of_observable /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by [].
qed.

lemma le_fs_shadow_semantic_post_good_branch_matches_programmed_view
  (obs : le_transcript_observable) :
  (le_fs_shadow_state_of_branch_observable obs false).`lefss_semantic_post_observable =
  le_fs_surrogate_transform obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable /le_fs_shadow_hidden_material_of_observable_branch.
by [].
qed.

lemma le_fs_shadow_semantic_post_of_observable_good_branch_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  (le_fs_shadow_state_of_branch_observable obs false).`lefss_semantic_post_observable =
  le_fs_surrogate_transform obs.
proof.
move=> _.
exact (le_fs_shadow_semantic_post_good_branch_matches_programmed_view obs).
qed.

lemma le_fs_shadow_semantic_post_bad_branch_matches_semantic_programmed_view
  (obs : le_transcript_observable) :
  (le_fs_shadow_state_of_branch_observable obs true).`lefss_semantic_post_observable =
  le_fs_shadow_semantic_programmed_view_of_observable obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_semantic_programmed_view_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
by [].
qed.

lemma le_fs_shadow_semantic_post_branch_imageE
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable =
  le_fs_shadow_semantic_branch_image_of_observable obs bad.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_semantic_branch_image_of_observable.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_semantic_programmed_view_of_observable.
case: bad => /=.
- by rewrite /le_fs_shadow_hidden_material_of_observable_branch.
by rewrite /le_fs_shadow_hidden_material_of_observable_branch.
qed.

lemma le_fs_shadow_semantic_post_differs_from_programmed_view_only_on_bad_branch
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable <>
    (le_fs_shadow_state_of_branch_observable obs bad).`lefss_post_observable =>
  bad.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_programmed_response_of_observable.
by case: bad => /=.
qed.

lemma le_fs_shadow_projected_post_branch_matches_surrogate
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_post_observable =
  le_fs_surrogate_transform obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
by [].
qed.
