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
require import LEFsProgrammingMarginalCategoryFacts.
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