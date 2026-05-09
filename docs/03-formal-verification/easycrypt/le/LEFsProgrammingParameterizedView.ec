require import QssmTypes.
require import AllCore Distr.
require import Real.
require import Ring.
require import SDist.
require import StdOrder.
require import LESurface.
require import LERealExecution.
require import LERejectionSampler.
require import LERejectionSamplerParameterizedCore.
require import LEFsProgrammingLiveParameterizedCore.
require import LEFsProgrammingLiveParameterizedMass.
require import LEFsProgrammingSurface.
require import LEFsProgrammingPostMarginal.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

op d_le_parameterized_pre_fs_semantic_programming_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingLiveParameterizedCore.d_le_parameterized_pre_fs_semantic_programming_view x s.

op d_le_parameterized_post_fs_semantic_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingLiveParameterizedCore.d_le_parameterized_post_fs_semantic_programmed_view x s.

op d_le_parameterized_fs_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_semantic_post_marginal x s.

lemma d_le_parameterized_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_parameterized_post_fs_semantic_programmed_view x s =
      dmap ((d_le_parameterized_pre_fs_semantic_programming_view x s) `*`
            dunit false)
        (fun (p : le_transcript_observable * bool) =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
            (fst p) (snd p)).
proof.
exact LEFsProgrammingLiveParameterizedCore.d_le_parameterized_post_fs_semantic_programmed_view_pairE.
qed.

lemma d_le_parameterized_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_parameterized_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_parameterized_pre_fs_semantic_programming_view x s) `*`
            LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
            (fst p) (snd p)).
proof.
exact LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_semantic_post_marginal_branch_split_pairE.
qed.

lemma A_LE_parameterized_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_parameterized_fs_shadow_semantic_post_marginal x s)
      (d_le_parameterized_post_fs_semantic_programmed_view x s)
      <= LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass.
proof.
exact LEFsProgrammingLiveParameterizedMass.A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_bad_branch_mass.
qed.

lemma A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget_from_parameterized_midpoint :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_parameterized_post_fs_semantic_programmed_view x s)
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s D _ _ _.
rewrite sdistC.
exact (LEFsProgrammingLiveParameterizedMass.A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_parameterized_budget x s).
qed.

lemma le_parameterized_distinguisher_event_on_semantic_branch_image_matches_surrogate
  (obs : le_transcript_observable) (bad : bool) (D : distinguisher) :
  le_distinguisher_event D
    (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad) =
  le_distinguisher_event D (le_fs_view_surrogate obs).
proof.
case: bad.
  rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable.
  rewrite /LEFsProgrammingShadowBranch.le_fs_shadow_semantic_branch_image_of_observable.
  rewrite /LEFsProgrammingShadowBranch.le_fs_shadow_semantic_programmed_view_of_observable.
  rewrite /LEFsProgrammingShadowBranch.le_fs_shadow_semantic_post_observable.
  rewrite /LEFsProgrammingShadowBranch.le_fs_shadow_hidden_material_of_observable_branch.
  rewrite /LEFsProgrammingCoreDefs.le_fs_programmed_response_of_observable.
  rewrite /LEFsProgrammingCoreDefs.le_fs_surrogate_transform.
  rewrite /le_distinguisher_event /le_qssm_event_payload /le_fs_view_surrogate /=.
  by [].
by rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
  /LEFsProgrammingShadowBranch.le_fs_shadow_semantic_branch_image_of_observable
  /LEFsProgrammingCoreDefs.le_fs_surrogate_transform.
qed.

lemma le_parameterized_distinguisher_event_on_demo_semantic_rejection_branch_image_matches_base
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) (D : distinguisher) :
  le_distinguisher_event D
    (LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable
      x s obs reject) =
  le_distinguisher_event D obs.
proof.
rewrite /LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /le_distinguisher_event /le_qssm_event_payload.
rewrite (LERealExecution.le_real_execution_semantic_rejection_observable_preserves_qssm_event_payload
  x s obs reject).
by [].
qed.

lemma le_parameterized_distinguisher_event_on_parameterized_rejection_branch_image_matches_base
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) (D : distinguisher) :
  le_distinguisher_event D
    (LERejectionSamplerParameterizedCore.le_rejection_parameterized_branch_image_of_observable
      x s obs reject) =
  le_distinguisher_event D obs.
proof.
rewrite /LERejectionSamplerParameterizedCore.le_rejection_parameterized_branch_image_of_observable.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /le_distinguisher_event /le_qssm_event_payload.
rewrite (LERealExecution.le_real_execution_semantic_rejection_observable_preserves_qssm_event_payload
  x s obs reject).
by [].
qed.

lemma le_parameterized_dmap_const_ll ['a 'b] (d : 'a distr) (v : 'b) :
  is_lossless d =>
  dmap d (fun _ : 'a => v) = dunit v.
proof.
move=> Hll.
rewrite /dmap dlet_cst_weight (is_losslessP _ Hll).
by rewrite dscalar1.
qed.

lemma le_view_distinguish_pr_parameterized_fs_shadow_semantic_post_marginal_matches_demo :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_distinguish_pr
      (d_le_parameterized_fs_shadow_semantic_post_marginal x s) D =
    le_view_distinguish_pr
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) D.
proof.
move=> x s D.
pose E := le_distinguisher_event D.
have Hdemo :
    dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E =
    dmap (dunit (le_real_execution_observable x s)) E.
  have Hfs :
      dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E =
      dmap (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s) E.
    rewrite (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
    rewrite (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view_pairE x s).
    rewrite !dmap_comp.
    rewrite !dmap_dprodE.
    apply (in_eq_dlet
      (fun obs =>
        dmap LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)))
      (fun obs =>
        dmap (dunit false)
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)))
      (LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view x s)).
    move=> obs _ /=.
    have Hconst : forall bad,
        E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad) =
        E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false).
      move=> bad.
      rewrite /E.
      by rewrite
        (le_parameterized_distinguisher_event_on_semantic_branch_image_matches_surrogate obs bad D)
        (le_parameterized_distinguisher_event_on_semantic_branch_image_matches_surrogate obs false D).
    have -> :
        dmap LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
        dmap LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
          (fun _ =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false)).
      apply eq_dmap=> bad /=.
      exact (Hconst bad).
    rewrite (le_parameterized_dmap_const_ll
      LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
      (E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false))
      LEFsProgrammingSurface.le_fs_shadow_branch_choice_lossless).
    by rewrite dmap_dunit.
  have Hcollapse :
      dmap (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s) E =
      dmap (LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view x s) E.
    rewrite /LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view.
    rewrite /LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view.
    rewrite dmap_comp /(\o).
    apply eq_dmap_in=> obs _ /=.
    rewrite /E.
    by rewrite (LEFsProgrammingSurface.le_fs_surrogate_transform_id obs).
  have Hrej :
      dmap (LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view x s) E =
      dmap (dunit (le_real_execution_observable x s)) E.
    rewrite /LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view.
    rewrite /LERejectionSampler.d_le_semantic_post_rejection_view.
    rewrite (LERejectionSampler.d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE x s).
    rewrite dmap_comp /(\o).
    have -> :
        dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
          (fun reject =>
            E (LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable
              x s (le_real_execution_observable x s) reject)) =
        dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
          (fun _ => E (le_real_execution_observable x s)).
      apply eq_dmap=> reject /=.
      rewrite /E.
      exact
        (le_parameterized_distinguisher_event_on_demo_semantic_rejection_branch_image_matches_base
          x s (le_real_execution_observable x s) reject D).
    rewrite (le_parameterized_dmap_const_ll
      LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
      (E (le_real_execution_observable x s))
      LERejectionSampler.le_rejection_shadow_semantic_branch_choice_lossless).
    by rewrite dmap_dunit.
  by rewrite Hfs Hcollapse Hrej.
have Hparam :
    dmap (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E =
    dmap (dunit (le_real_execution_observable x s)) E.
  have Hfs :
      dmap (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E =
      dmap (d_le_parameterized_post_fs_semantic_programmed_view x s) E.
    rewrite (d_le_parameterized_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
    rewrite (d_le_parameterized_post_fs_semantic_programmed_view_pairE x s).
    rewrite !dmap_comp.
    rewrite !dmap_dprodE.
    apply (in_eq_dlet
      (fun obs =>
        dmap LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)))
      (fun obs =>
        dmap (dunit false)
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)))
      (d_le_parameterized_pre_fs_semantic_programming_view x s)).
    move=> obs _ /=.
    have Hconst : forall bad,
        E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad) =
        E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false).
      move=> bad.
      rewrite /E.
      by rewrite
        (le_parameterized_distinguisher_event_on_semantic_branch_image_matches_surrogate obs bad D)
        (le_parameterized_distinguisher_event_on_semantic_branch_image_matches_surrogate obs false D).
    have -> :
        dmap LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice
          (fun bad =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
        dmap LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice
          (fun _ =>
            E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false)).
      apply eq_dmap=> bad /=.
      exact (Hconst bad).
    rewrite (le_parameterized_dmap_const_ll
      LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice
      (E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false))
      LEFsProgrammingLiveParameterizedCore.d_le_fs_parameterized_shadow_branch_choice_lossless).
    by rewrite dmap_dunit.
  have Hcollapse :
      dmap (d_le_parameterized_post_fs_semantic_programmed_view x s) E =
      dmap (d_le_parameterized_pre_fs_semantic_programming_view x s) E.
    rewrite /d_le_parameterized_post_fs_semantic_programmed_view.
    rewrite /d_le_parameterized_pre_fs_semantic_programming_view.
    rewrite dmap_comp /(\o).
    apply eq_dmap_in=> obs _ /=.
    rewrite /E.
    by rewrite (LEFsProgrammingSurface.le_fs_surrogate_transform_id obs).
  have Hrej :
      dmap (d_le_parameterized_pre_fs_semantic_programming_view x s) E =
      dmap (dunit (le_real_execution_observable x s)) E.
    rewrite /d_le_parameterized_pre_fs_semantic_programming_view.
    rewrite /d_le_parameterized_post_rejection_view.
    rewrite (LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_post_marginal_fixed_branch_imageE x s).
    rewrite dmap_comp /(\o).
    have -> :
        dmap LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_branch_choice
          (fun reject =>
            E (LERejectionSamplerParameterizedCore.le_rejection_parameterized_branch_image_of_observable
              x s (le_real_execution_observable x s) reject)) =
        dmap LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_branch_choice
          (fun _ => E (le_real_execution_observable x s)).
      apply eq_dmap=> reject /=.
      rewrite /E.
      exact
        (le_parameterized_distinguisher_event_on_parameterized_rejection_branch_image_matches_base
          x s (le_real_execution_observable x s) reject D).
    rewrite (le_parameterized_dmap_const_ll
      LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_branch_choice
      (E (le_real_execution_observable x s))
      LERejectionSamplerParameterizedCore.d_le_rejection_parameterized_branch_choice_lossless).
    by rewrite dmap_dunit.
  by rewrite Hfs Hcollapse Hrej.
have Hmapped :
    dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E =
    dmap (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E.
  by rewrite Hdemo Hparam.
rewrite /le_view_distinguish_pr.
have Hmu :
    mu1 (dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E) true =
    mu1 (dmap (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E) true.
  by rewrite Hmapped.
have Hleft :
    mu1 (dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E) true =
    mu (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E.
  rewrite dmap1E.
  apply mu_eq=> obs /=.
  rewrite /pred1 /(\o).
  by case: (E obs).
have Hright :
    mu1 (dmap (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E) true =
    mu (d_le_parameterized_fs_shadow_semantic_post_marginal x s) E.
  rewrite dmap1E.
  apply mu_eq=> obs /=.
  rewrite /pred1 /(\o).
  by case: (E obs).
move: Hmu.
rewrite Hleft Hright.
move=> Hmu_eq.
by rewrite Hmu_eq.
qed.