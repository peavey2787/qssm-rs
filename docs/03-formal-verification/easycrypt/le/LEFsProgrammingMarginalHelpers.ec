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
