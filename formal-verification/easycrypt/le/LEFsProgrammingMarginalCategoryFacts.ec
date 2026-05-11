require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require import LEFsProgrammingMarginalStateFacts.
require BudgetParameters.

(*---*) import RealOrder.

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
