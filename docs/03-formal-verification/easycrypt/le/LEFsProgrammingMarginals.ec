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
require BudgetParameters.

(*---*) import RealOrder.

lemma le_fs_marginals_branch_choice_lossless :
  is_lossless d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_lossless.
qed.

lemma le_fs_marginals_good_branch_has_support :
  false \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_good_branch_has_support.
qed.

lemma le_fs_marginals_bad_branch_has_support :
  true \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_bad_branch_has_support.
qed.

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

lemma le_fs_shadow_semantic_bad_event_category_stateE
  (obs : le_transcript_observable)
  (category : BudgetParameters.le_fs_semantic_branch_category) :
  le_fs_shadow_semantic_bad_event
    (le_fs_shadow_state_of_category_observable obs category) =
  BudgetParameters.le_fs_semantic_branch_category_is_failure category.
proof.
rewrite /le_fs_shadow_state_of_category_observable.
exact (le_fs_shadow_semantic_bad_event_branch_stateE obs
  (BudgetParameters.le_fs_semantic_branch_category_is_failure category)).
qed.

lemma le_fs_shadow_clean_category_has_no_semantic_failure
  (obs : le_transcript_observable) :
  ! le_fs_shadow_semantic_bad_event
      (le_fs_shadow_state_of_category_observable obs
        BudgetParameters.LEFSSemanticBranchClean).
proof.
rewrite le_fs_shadow_semantic_bad_event_category_stateE.
by rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
qed.

lemma le_fs_shadow_query_collision_category_has_semantic_failure
  (obs : le_transcript_observable) :
  le_fs_shadow_semantic_bad_event
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchQueryCollision).
proof.
rewrite le_fs_shadow_semantic_bad_event_category_stateE.
by rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
qed.

lemma le_fs_shadow_programming_collision_category_has_semantic_failure
  (obs : le_transcript_observable) :
  le_fs_shadow_semantic_bad_event
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchProgrammingCollision).
proof.
rewrite le_fs_shadow_semantic_bad_event_category_stateE.
by rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
qed.

lemma le_fs_shadow_transcript_mismatch_category_has_semantic_failure
  (obs : le_transcript_observable) :
  le_fs_shadow_semantic_bad_event
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchTranscriptMismatch).
proof.
rewrite le_fs_shadow_semantic_bad_event_category_stateE.
by rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
qed.

lemma le_fs_shadow_clean_condition_clean_categoryE
  (obs : le_transcript_observable) :
  le_fs_shadow_clean_condition
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchClean).
proof.
rewrite /le_fs_shadow_clean_condition /le_fs_shadow_state_of_category_observable.
rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
rewrite (le_fs_shadow_semantic_bad_event_branch_stateE obs false).
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable /le_fs_shadow_hidden_material_of_observable_branch /=.
by [].
qed.

lemma le_fs_shadow_query_collision_condition_query_collision_categoryE
  (obs : le_transcript_observable) :
  le_fs_shadow_query_collision_condition
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchQueryCollision).
proof.
rewrite /le_fs_shadow_query_collision_condition /le_fs_shadow_state_of_category_observable.
rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
rewrite (le_fs_shadow_semantic_bad_event_branch_stateE obs true).
rewrite /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_query_row_of_observable.
rewrite /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs /=.
by [].
qed.

lemma le_fs_shadow_programming_collision_condition_programming_collision_categoryE
  (obs : le_transcript_observable) :
  le_fs_shadow_programming_collision_condition
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchProgrammingCollision).
proof.
rewrite /le_fs_shadow_programming_collision_condition /le_fs_shadow_state_of_category_observable.
rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
rewrite (le_fs_shadow_semantic_bad_event_branch_stateE obs true).
rewrite /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_query_row_of_observable.
rewrite /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_fs_shadow_programming_log_of_observable.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs /=.
by [].
qed.

lemma le_fs_shadow_transcript_mismatch_condition_transcript_mismatch_categoryE
  (obs : le_transcript_observable) :
  le_fs_shadow_transcript_mismatch_condition
    (le_fs_shadow_state_of_category_observable obs
      BudgetParameters.LEFSSemanticBranchTranscriptMismatch).
proof.
rewrite /le_fs_shadow_transcript_mismatch_condition /le_fs_shadow_state_of_category_observable.
rewrite /BudgetParameters.le_fs_semantic_branch_category_is_failure /pred1 /=.
rewrite (le_fs_shadow_semantic_bad_event_branch_stateE obs true).
rewrite /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_shadow_semantic_post_observable.
rewrite /le_fs_programmed_response_of_observable.
rewrite /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs /le_fs_query_material_obs /=.
by [].
qed.

lemma le_fs_shadow_semantic_category_condition_stateE
  (obs : le_transcript_observable)
  (category : BudgetParameters.le_fs_semantic_branch_category) :
  le_fs_shadow_semantic_category_condition category
    (le_fs_shadow_state_of_category_observable obs category).
proof.
case: category=> /=.
- exact (le_fs_shadow_clean_condition_clean_categoryE obs).
- exact (le_fs_shadow_query_collision_condition_query_collision_categoryE obs).
- exact (le_fs_shadow_programming_collision_condition_programming_collision_categoryE obs).
exact (le_fs_shadow_transcript_mismatch_condition_transcript_mismatch_categoryE obs).
qed.

lemma le_fs_shadow_dmap_dprod_fst_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
rewrite (dprod_marginalL da db (fun (a : 'a) => a)).
rewrite dmap_id.
have Hw : weight db = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma le_fs_shadow_dmap_dprod_snd_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw : weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma d_le_pre_fs_programming_view_dunit
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
proof.
rewrite /d_le_pre_fs_programming_view /d_le_post_rejection_view.
rewrite /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit.
by rewrite /le_post_rejection_surrogate.
qed.

lemma d_le_pre_fs_programming_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_pre_fs_programming_view x s).
proof.
rewrite (d_le_pre_fs_programming_view_dunit x s).
rewrite /is_lossless /weight dunitE /=.
by [].
qed.

lemma d_le_pre_fs_semantic_programming_view_fixed_branch_imageE
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_semantic_programming_view x s =
    dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
      (fun reject =>
        LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable
          x s (le_real_execution_observable x s) reject).
proof.
rewrite /d_le_pre_fs_semantic_programming_view.
rewrite /LERejectionSampler.d_le_semantic_post_rejection_view.
exact (LERejectionSampler.d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE x s).
qed.

lemma d_le_pre_fs_semantic_programming_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_pre_fs_semantic_programming_view x s).
proof.
rewrite (d_le_pre_fs_semantic_programming_view_fixed_branch_imageE x s).
apply dmap_ll.
exact LERejectionSampler.le_rejection_shadow_semantic_branch_choice_lossless.
qed.

lemma d_le_fs_shadow_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_coupled_state x s =
      dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
proof.
by move=> x s; rewrite /d_le_fs_shadow_coupled_state.
qed.

lemma d_le_fs_shadow_semantic_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_coupled_state x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
proof.
by move=> x s; rewrite /d_le_fs_shadow_semantic_coupled_state.
qed.

lemma le_fs_shadow_semantic_branch_state_has_support
  (x : qssm_public_input) (s : seed)
  (obs : le_transcript_observable) (bad : bool) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  bad \in d_le_fs_shadow_branch_choice =>
  le_fs_shadow_state_of_branch_observable obs bad \in d_le_fs_shadow_semantic_coupled_state x s.
proof.
move=> Hobs Hbad.
rewrite (d_le_fs_shadow_semantic_coupled_state_pairE x s).
rewrite supp_dmap.
exists (obs, bad); split.
  by rewrite supp_dprod Hobs Hbad.
by [].
qed.

lemma le_fs_shadow_semantic_good_branch_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_shadow_state_of_branch_observable obs false \in d_le_fs_shadow_semantic_coupled_state x s.
proof.
move=> Hobs.
exact (le_fs_shadow_semantic_branch_state_has_support x s obs false Hobs
  le_fs_marginals_good_branch_has_support).
qed.

lemma le_fs_shadow_semantic_bad_branch_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_shadow_state_of_branch_observable obs true \in d_le_fs_shadow_semantic_coupled_state x s.
proof.
move=> Hobs.
exact (le_fs_shadow_semantic_branch_state_has_support x s obs true Hobs
  le_fs_marginals_bad_branch_has_support).
qed.

lemma le_fs_shadow_bad_event_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
move=> _.
exact (le_fs_shadow_bad_event_stateE obs).
qed.

lemma le_real_execution_query_material_bad_flag_false
  (x : qssm_public_input) (s : seed) :
  ! (le_real_execution_query_material x s).`leqm_bad_flag.
proof.
rewrite /le_real_execution_query_material /le_real_execution_record_of.
rewrite /le_real_execution_query_material_of_spine /le_real_execution_spine_of.
rewrite /le_real_execution_primitive_material_of /le_real_execution_residual_material_of.
rewrite /le_real_execution_hidden_query_material_of.
by [].
qed.

lemma d_le_pre_fs_programming_view_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  obs = le_real_execution_observable x s.
proof.
move=> Hobs.
rewrite /d_le_pre_fs_programming_view /d_le_post_rejection_view.
rewrite /d_le_real_view /d_le_real_execution_view in Hobs.
case/supp_dmap: Hobs=> pre_obs [Hpre ->].
move: Hpre; rewrite supp_dunit => ->.
by rewrite /le_post_rejection_surrogate.
qed.

lemma le_fs_shadow_good_event_on_pre_programming_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_good_event x s obs.
proof.
move=> Hobs.
rewrite /le_fs_shadow_good_event /le_fs_query_material_obs.
rewrite (d_le_pre_fs_programming_view_supportE x s obs Hobs).
rewrite (le_real_execution_observable_exposes_query_material x s).
exact (le_real_execution_query_material_bad_flag_false x s).
qed.

lemma le_fs_shadow_post_of_observable_good_branch_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_post_of_observable obs
    (le_fs_shadow_hidden_material_of_observable obs) =
  le_fs_surrogate_transform obs.
proof.
move=> Hobs.
have Hgood := le_fs_shadow_good_event_on_pre_programming_support x s obs Hobs.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
move: Hgood.
rewrite /le_fs_shadow_good_event /le_fs_query_material_obs.
by case: (obs.`leto_query_material.`leqm_bad_flag).
qed.

lemma le_fs_shadow_good_branch_post_matches_surrogate_on_pre_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_good_event x s obs =>
  le_fs_shadow_post_of_observable obs
    (le_fs_shadow_hidden_material_of_observable obs) =
  le_fs_surrogate_transform obs.
proof.
move=> Hobs _.
exact (le_fs_shadow_post_of_observable_good_branch_supportE x s obs Hobs).
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

lemma d_le_fs_shadow_post_marginal_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_post_fs_programmed_view x s.
proof.
move=> x s.
have Hcollapse :
  dmap (d_le_pre_fs_programming_view x s)
    (fun (obs : le_transcript_observable) =>
      le_fs_shadow_post_of_observable obs
        (le_fs_shadow_hidden_material_of_observable obs)) =
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.
  apply eq_dmap_in=> obs Hobs /=.
  exact (le_fs_shadow_post_of_observable_good_branch_supportE x s obs Hobs).
rewrite /d_le_fs_shadow_post_marginal.
rewrite /d_le_fs_shadow_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_post_observable
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_post_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_post_of_observable (fst p)
        (le_fs_shadow_hidden_material_of_observable (fst p))).
  apply eq_dmap_in=> p Hp /=.
  case: p Hp=> obs bad Hp /=.
  move: Hp; rewrite supp_dprod => -[Hobs _].
  rewrite /le_fs_shadow_post_observable /(\o).
  rewrite (le_fs_shadow_projected_post_branch_matches_surrogate obs bad).
  by rewrite (le_fs_shadow_post_of_observable_good_branch_supportE x s obs Hobs).
rewrite Hmap.
rewrite -(dmap_comp fst
  (fun (obs : le_transcript_observable) =>
    le_fs_shadow_post_of_observable obs
      (le_fs_shadow_hidden_material_of_observable obs))
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
rewrite (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_marginals_branch_choice_lossless).
rewrite Hcollapse.
by rewrite /d_le_post_fs_programmed_view.
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_good_branch_image x s =
    d_le_post_fs_semantic_programmed_view x s.
proof.
by move=> x s; rewrite /d_le_fs_shadow_semantic_good_branch_image
  /d_le_post_fs_semantic_programmed_view.
qed.

lemma d_le_post_fs_semantic_programmed_view_good_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_semantic_programmed_view x s =
      dmap (d_le_pre_fs_semantic_programming_view x s)
        (fun (obs : le_transcript_observable) =>
          (le_fs_shadow_state_of_branch_observable obs false).`lefss_semantic_post_observable).
proof.
move=> x s.
rewrite /d_le_post_fs_semantic_programmed_view.
apply eq_dmap_in=> obs Hobs /=.
rewrite (le_fs_shadow_semantic_post_of_observable_good_branch_supportE x s obs Hobs).
by [].
qed.

lemma d_le_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_semantic_programmed_view x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit false)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_post_fs_semantic_programmed_view_good_branch_imageE x s).
rewrite dmap_dprodE.
have -> :
    dlet (d_le_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit false)
        (fun bad => le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
    dlet (d_le_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit obs)
        (fun (obs' : le_transcript_observable) =>
          (le_fs_shadow_state_of_branch_observable obs' false).`lefss_semantic_post_observable)).
  apply (in_eq_dlet
    (fun obs => dmap (dunit false)
      (fun bad => le_fs_shadow_semantic_branch_image_of_observable obs bad))
    (fun obs => dmap (dunit obs)
      (fun (obs' : le_transcript_observable) =>
        (le_fs_shadow_state_of_branch_observable obs' false).`lefss_semantic_post_observable))
    (d_le_pre_fs_semantic_programming_view x s)).
  move=> obs Hobs /=.
  rewrite !dmap_dunit /=.
  rewrite /le_fs_shadow_semantic_branch_image_of_observable.
  rewrite (le_fs_shadow_semantic_post_of_observable_good_branch_supportE x s obs Hobs).
  by [].
rewrite -dmap_dlet.
rewrite dlet_d_unit.
by [].
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_bad_branch_image x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit true)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
move=> x s.
rewrite /d_le_fs_shadow_semantic_bad_branch_image.
rewrite dmap_dprodE.
have -> :
    dlet (d_le_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit true)
        (fun bad => le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
    dlet (d_le_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit obs) le_fs_shadow_semantic_programmed_view_of_observable).
  apply (in_eq_dlet
    (fun obs => dmap (dunit true)
      (fun bad => le_fs_shadow_semantic_branch_image_of_observable obs bad))
    (fun obs => dmap (dunit obs) le_fs_shadow_semantic_programmed_view_of_observable)
    (d_le_pre_fs_semantic_programming_view x s)).
  move=> obs _ /=.
  rewrite !dmap_dunit /=.
  by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
rewrite -dmap_dlet.
rewrite dlet_d_unit.
by [].
qed.

lemma d_le_post_fs_programmed_view_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_programmed_view x s =
      dmap (dunit false)
        (fun bad =>
          le_fs_shadow_semantic_branch_image_of_observable
            (le_real_execution_observable x s) bad).
proof.
move=> x s.
rewrite /d_le_post_fs_programmed_view.
rewrite (d_le_pre_fs_programming_view_dunit x s).
rewrite !dmap_dunit /=.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
qed.

lemma d_le_fs_shadow_post_marginal_matches_sim_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_sim_view x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_post_marginal_matches_programmed_view.
by rewrite /d_le_post_fs_programmed_view /d_le_pre_fs_programming_view
  /d_le_sim_view /le_fs_surrogate_transform.
qed.

lemma le_fs_surrogate_transform_id
  (obs : le_transcript_observable) :
  le_fs_surrogate_transform obs = obs.
proof.
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
by rewrite /le_fs_surrogate_transform /le_fs_view_surrogate
  /le_fs_program_query_material.
qed.

lemma d_le_fs_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view.
rewrite d_le_fs_shadow_post_marginal_matches_programmed_view.
rewrite /d_le_post_fs_programmed_view.
have Hmap :
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform =
  dmap (d_le_pre_fs_programming_view x s)
    (fun (obs : le_transcript_observable) => obs).
  apply eq_dmap_in=> obs _ /=.
  exact (le_fs_surrogate_transform_id obs).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_fs_shadow_state_of_branch_observable (fst p) (snd p)).`lefss_semantic_post_observable).
proof.
move=> x s.
rewrite /d_le_fs_shadow_semantic_post_marginal.
rewrite /d_le_fs_shadow_semantic_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_semantic_post_state_observable
  ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
apply eq_dmap_in=> p _ /=.
case: p=> obs bad /=.
by rewrite /le_fs_shadow_semantic_post_state_observable /(\o).
qed.

lemma d_le_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s).
apply eq_dmap_in=> p _ /=.
case: p=> obs bad /=.
exact (le_fs_shadow_semantic_post_branch_imageE obs bad).
qed.