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
require import LEFsProgrammingMarginals.
require BudgetParameters.

(*---*) import RealOrder.

lemma le_fs_support_images_good_branch_has_support :
  false \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_good_branch_has_support.
qed.

lemma le_fs_support_images_bad_branch_has_support :
  true \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_bad_branch_has_support.
qed.

lemma le_real_execution_observable_in_pre_fs_semantic_programming_view
  (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_pre_fs_semantic_programming_view x s.
proof.
rewrite (d_le_pre_fs_semantic_programming_view_fixed_branch_imageE x s).
rewrite supp_dmap.
exists false; split.
  exact LERejectionSampler.le_rejection_shadow_semantic_accept_branch_has_support.
rewrite /LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable.
have Hacc :
    le_real_execution_observable x s =
    LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch
      x s (le_real_execution_observable x s) false.
  by rewrite eq_sym
    (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id
      x s (le_real_execution_observable x s)).
exact Hacc.
qed.

lemma le_fs_shadow_semantic_post_marginal_support
  (x : qssm_public_input) (s : seed)
  (obs : le_transcript_observable) (bad : bool) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  bad \in d_le_fs_shadow_branch_choice =>
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hobs Hbad.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s).
rewrite supp_dmap.
exists (obs, bad); split.
  by rewrite supp_dprod Hobs Hbad.
by [].
qed.

lemma le_fs_shadow_semantic_post_good_branch_support
  (x : qssm_public_input) (s : seed) :
  (le_fs_shadow_state_of_branch_observable
     (le_real_execution_observable x s) false).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
apply (le_fs_shadow_semantic_post_marginal_support x s
  (le_real_execution_observable x s) false).
  exact (le_real_execution_observable_in_pre_fs_semantic_programming_view x s).
exact le_fs_support_images_good_branch_has_support.
qed.

lemma le_fs_shadow_semantic_post_bad_branch_support
  (x : qssm_public_input) (s : seed) :
  (le_fs_shadow_state_of_branch_observable
     (le_real_execution_observable x s) true).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
apply (le_fs_shadow_semantic_post_marginal_support x s
  (le_real_execution_observable x s) true).
  exact (le_real_execution_observable_in_pre_fs_semantic_programming_view x s).
exact le_fs_support_images_bad_branch_has_support.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_semantic_post_marginal x s =>
  exists (pre_obs : le_transcript_observable) (bad : bool),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    bad \in d_le_fs_shadow_branch_choice /\
    obs =
      (le_fs_shadow_state_of_branch_observable pre_obs bad).`lefss_semantic_post_observable.
proof.
move=> Hobs.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s) in Hobs.
case/supp_dmap: Hobs=> -[pre_obs bad] [Hp ->].
move: Hp; rewrite supp_dprod => -[Hpre Hbad].
exists pre_obs.
exists bad.
by [].
qed.

lemma le_fs_shadow_semantic_good_branch_image_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_surrogate_transform obs
    \in d_le_fs_shadow_semantic_good_branch_image x s.
proof.
move=> Hobs.
rewrite /d_le_fs_shadow_semantic_good_branch_image.
rewrite /LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_good_branch_image.
rewrite /d_le_post_fs_semantic_programmed_view.
rewrite supp_dmap.
exists obs; split.
  exact Hobs.
by [].
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_supportE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_good_branch_image x s =>
  exists (pre_obs : le_transcript_observable),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs = le_fs_surrogate_transform pre_obs.
proof.
move=> Hpost.
rewrite /d_le_fs_shadow_semantic_good_branch_image in Hpost.
rewrite /LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_good_branch_image in Hpost.
rewrite /d_le_post_fs_semantic_programmed_view in Hpost.
case/supp_dmap: Hpost=> pre_obs [Hpre ->].
exists pre_obs; split.
  exact Hpre.
by [].
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_support_sub_postE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_good_branch_image x s =>
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hpost.
have [pre_obs [Hpre Himage]] :=
  d_le_fs_shadow_semantic_good_branch_image_supportE x s post_obs Hpost.
have Hgood :
    (le_fs_shadow_state_of_branch_observable pre_obs false).`lefss_semantic_post_observable
      \in d_le_fs_shadow_semantic_post_marginal x s.
  exact (le_fs_shadow_semantic_post_marginal_support x s pre_obs false Hpre
    le_fs_support_images_good_branch_has_support).
rewrite (le_fs_shadow_semantic_post_of_observable_good_branch_supportE x s pre_obs Hpre) in Hgood.
rewrite Himage.
exact Hgood.
qed.

lemma le_fs_shadow_semantic_bad_branch_image_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_shadow_semantic_programmed_view_of_observable obs
    \in d_le_fs_shadow_semantic_bad_branch_image x s.
proof.
move=> Hobs.
rewrite (d_le_fs_shadow_semantic_bad_branch_image_pairE x s).
rewrite supp_dmap.
exists (obs, true); split.
  by rewrite supp_dprod Hobs supp_dunit.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_supportE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_bad_branch_image x s =>
  exists (pre_obs : le_transcript_observable),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs = le_fs_shadow_semantic_programmed_view_of_observable pre_obs.
proof.
move=> Hpost.
rewrite (d_le_fs_shadow_semantic_bad_branch_image_pairE x s) in Hpost.
case/supp_dmap: Hpost=> -[pre_obs bad] [Hp ->].
move: Hp; rewrite supp_dprod supp_dunit => -[Hpre ->].
exists pre_obs; split.
  exact Hpre.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_support_sub_postE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_bad_branch_image x s =>
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hpost.
have [pre_obs [Hpre Himage]] :=
  d_le_fs_shadow_semantic_bad_branch_image_supportE x s post_obs Hpost.
have Hbad :
    (le_fs_shadow_state_of_branch_observable pre_obs true).`lefss_semantic_post_observable
      \in d_le_fs_shadow_semantic_post_marginal x s.
  exact (le_fs_shadow_semantic_post_marginal_support x s pre_obs true Hpre
    le_fs_support_images_bad_branch_has_support).
rewrite (le_fs_shadow_semantic_post_bad_branch_matches_semantic_programmed_view pre_obs) in Hbad.
rewrite Himage.
exact Hbad.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_support_tagged_imageE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s =>
  exists (pre_obs : le_transcript_observable) (b : bool),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs =
      le_fs_shadow_semantic_branch_image_of_observable pre_obs b.
proof.
move=> Hpost.
rewrite (d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s) in Hpost.
case/supp_dmap: Hpost=> -[pre_obs b] [Hp ->].
move: Hp; rewrite supp_dprod => -[Hpre _].
exists pre_obs; exists b; split.
  exact Hpre.
by [].
qed.
