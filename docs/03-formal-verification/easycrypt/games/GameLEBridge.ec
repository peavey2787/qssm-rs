require import AllCore List Distr.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem.
require BudgetParameters.
require import SourceDistributions SourceTheorem MS LERealExecution LESurface LEModel LERejectionSampler LEStatisticalDistance LEHVZK.
require import LEFsProgrammingSurface.
require import LEFsProgrammingShadowBranch LEFsProgrammingCoreDefs.
require import GameTypes GameViews GameAdvantage.

pred le_game_bridge_consistent
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) =
  Adv_G1_G2_LE x xms s D = le_game_hop_adv x s D.

op le_view_of_game : game_view -> le_transcript_observable.

op le_real_view_from_G1
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) : le_transcript_observable =
  le_view_of_game (G1_le_real_projection x xms s).

op le_sim_view_from_G2
  (x : qssm_public_input) (s : seed) : le_transcript_observable =
  le_view_of_game (G2_full_sim x s).

pred le_real_view_projects_from_G1 (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  le_view_of_game (G1_le_real_projection x xms s) = le_real_view_from_G1 x xms s.

pred le_sim_view_projects_from_G2 (x : qssm_public_input) (s : seed) =
  le_view_of_game (G2_full_sim x s) = le_sim_view_from_G2 x s.

lemma A_G1_LE_view_constructor_correct :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    le_view_of_game (G1_le_real_projection x xms s) = le_real_view_from_G1 x xms s.
proof.
by rewrite /le_real_view_from_G1.
qed.

lemma A_G2_LE_view_constructor_correct :
  forall (x : qssm_public_input) (s : seed),
    le_view_of_game (G2_full_sim x s) = le_sim_view_from_G2 x s.
proof.
by rewrite /le_sim_view_from_G2.
qed.

lemma A_G1_LE_view_projects_to_real :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_real_view_projects_from_G1 x xms s.
proof.
move=> x xms s D.
rewrite /le_real_view_projects_from_G1.
exact (A_G1_LE_view_constructor_correct x xms s).
qed.

lemma A_G2_LE_view_projects_to_sim :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_sim_view_projects_from_G2 x s.
proof.
move=> x xms s D.
rewrite /le_sim_view_projects_from_G2.
exact (A_G2_LE_view_constructor_correct x s).
qed.

op le_projected_real_adv
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  le_projected_real_adv_base x s D.

lemma A_LE_projected_real_adv_layout :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_projected_real_adv x xms s D = le_projected_real_adv_base x s D.
proof.
by rewrite /le_projected_real_adv.
qed.

op le_projected_sim_adv
  (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_projected_sim_adv_base x s D.

lemma A_LE_projected_sim_adv_layout :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_projected_sim_adv x s D = le_projected_sim_adv_base x s D.
proof.
by rewrite /le_projected_sim_adv.
qed.

op game_pr_le_projected
  (is_real : bool) (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  if is_real
  then le_view_distinguish_pr (d_le_real_view x s) D
  else le_view_distinguish_pr (d_le_sim_view x s) D.

(* Exact G1/G2 LE projection semantics are now definitional on the split view
   constructors. *)
lemma A_game_pr_LE_projection_semantics :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_le_real_projection x xms s) D = game_pr_le_projected true x s D /\
    game_pr (G2_full_sim x s) D = game_pr_le_projected false x s D.
proof.
move=> x xms s D.
rewrite /game_pr /G1_le_real_projection /G2_full_sim.
rewrite /game_pr_g1_le_core /game_pr_g2_core /game_pr_le_projected /=.
by split.
qed.

lemma A_game_pr_on_G1_uses_LE_real_projection :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_le_real_projection x xms s) D =
      le_view_distinguish_pr (d_le_real_view x s) D.
proof.
move=> x xms s D.
have [Hg1 _] := A_game_pr_LE_projection_semantics x xms s D.
rewrite Hg1 /game_pr_le_projected /=.
by [].
qed.

lemma A_game_pr_on_G2_uses_LE_sim_projection :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    game_pr (G2_full_sim x s) D =
      le_view_distinguish_pr (d_le_sim_view x s) D.
proof.
move=> x s D.
rewrite /game_pr /G2_full_sim /game_pr_g2_core /game_pr_le_projected /=.
by [].
qed.

lemma A_game_pr_G1_LE_real_view_correct :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_le_real_projection x xms s) D =
      le_view_distinguish_pr (d_le_real_view x s) D.
proof.
move=> x xms s D.
exact (A_game_pr_on_G1_uses_LE_real_projection x xms s D).
qed.

lemma A_game_pr_G2_LE_sim_view_correct :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    game_pr (G2_full_sim x s) D =
      le_view_distinguish_pr (d_le_sim_view x s) D.
proof.
move=> x s D.
exact (A_game_pr_on_G2_uses_LE_sim_projection x s D).
qed.

lemma A_game_pr_G1_equals_projected_real :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_le_real_projection x xms s) D = le_projected_real_adv x xms s D.
proof.
move=> x xms s D.
rewrite /le_projected_real_adv /le_projected_real_adv_base.
exact (A_game_pr_on_G1_uses_LE_real_projection x xms s D).
qed.

lemma A_game_pr_G2_equals_projected_sim :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    game_pr (G2_full_sim x s) D = le_projected_sim_adv x s D.
proof.
move=> x s D.
rewrite /le_projected_sim_adv /le_projected_sim_adv_base.
exact (A_game_pr_on_G2_uses_LE_sim_projection x s D).
qed.

lemma A_Adv_G1_G2_LE_unfolds_to_projected_views :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    Adv_G1_G2_LE x xms s D =
      le_projected_real_adv x xms s D - le_projected_sim_adv x s D.
proof.
move=> x xms s D.
rewrite /Adv_G1_G2_LE.
rewrite (Adv_def (G1_le_real_projection x xms s) (G2_full_sim x s) D).
rewrite (A_game_pr_G1_equals_projected_real x xms s D).
rewrite (A_game_pr_G2_equals_projected_sim x s D).
done.
qed.

lemma A_le_game_hop_adv_unfolds_to_projected_views :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_game_hop_adv x s D =
      le_projected_real_adv x xms s D - le_projected_sim_adv x s D.
proof.
move=> x xms s D.
rewrite /le_game_hop_adv.
rewrite -(A_LE_projected_real_adv_layout x xms s D).
rewrite -(A_LE_projected_sim_adv_layout x s D).
done.
qed.

lemma A_LE_real_projected_view_matches_G1 :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_real_view_projects_from_G1 x xms s =>
    Adv_G1_G2_LE x xms s D =
      le_projected_real_adv x xms s D - le_projected_sim_adv x s D.
proof.
move=> x xms s D _.
exact (A_Adv_G1_G2_LE_unfolds_to_projected_views x xms s D).
qed.

lemma A_LE_sim_projected_view_matches_G2 :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_sim_view_projects_from_G2 x s =>
    le_game_hop_adv x s D =
      le_projected_real_adv x xms s D - le_projected_sim_adv x s D.
proof.
move=> x xms s D _.
exact (A_le_game_hop_adv_unfolds_to_projected_views x xms s D).
qed.

lemma A_LE_projected_adv_matches_game_adv :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_real_view_projects_from_G1 x xms s =>
    le_sim_view_projects_from_G2 x s =>
    Adv_G1_G2_LE x xms s D = le_game_hop_adv x s D.
proof.
move=> x xms s D HG1 HG2.
have HG1eq := A_LE_real_projected_view_matches_G1 x xms s D HG1.
have HG2eq := A_LE_sim_projected_view_matches_G2 x xms s D HG2.
by rewrite HG1eq HG2eq.
qed.

lemma A_LE_game_bridge_consistency :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    le_game_bridge_consistent x xms s D.
proof.
move=> x xms s D.
have HG1 : le_real_view_projects_from_G1 x xms s by exact (A_G1_LE_view_projects_to_real x xms s D).
have HG2 : le_sim_view_projects_from_G2 x s by exact (A_G2_LE_view_projects_to_sim x xms s D).
rewrite /le_game_bridge_consistent.
exact (A_LE_projected_adv_matches_game_adv x xms s D HG1 HG2).
qed.

lemma le_distinguisher_event_on_semantic_branch_image_matches_surrogate
  (obs : le_transcript_observable) (bad : bool) (D : distinguisher) :
  le_distinguisher_event D
    (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad) =
  le_distinguisher_event D (le_fs_view_surrogate obs).
proof.
case: bad.
- rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable.
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

lemma dmap_const_ll ['a 'b] (d : 'a distr) (v : 'b) :
  is_lossless d =>
  dmap d (fun _ : 'a => v) = dunit v.
proof.
move=> ll_d.
rewrite /dmap dlet_cst_weight (is_losslessP _ ll_d).
by rewrite dscalar1.
qed.

lemma le_distinguisher_event_on_semantic_rejection_branch_image_matches_base
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

lemma A_LE_semantic_projected_sim_adv_layout :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_projected_sim_adv x s D =
      le_view_distinguish_pr
        (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) D.
proof.
move=> x s D.
pose E := le_distinguisher_event D.
have Hfs :
    dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E =
    dmap (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s) E.
- rewrite (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
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
  - move=> bad.
    rewrite /E.
    by rewrite (le_distinguisher_event_on_semantic_branch_image_matches_surrogate obs bad D)
      (le_distinguisher_event_on_semantic_branch_image_matches_surrogate obs false D).
  have -> :
      dmap LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
        (fun bad =>
          E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
      dmap LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
        (fun _ =>
          E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false)).
  - apply eq_dmap => bad /=.
    exact (Hconst bad).
  rewrite (dmap_const_ll LEFsProgrammingSurface.d_le_fs_shadow_branch_choice
    (E (LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs false))
    LEFsProgrammingSurface.le_fs_shadow_branch_choice_lossless).
  by rewrite dmap_dunit.
have Hcollapse :
    dmap (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s) E =
    dmap (LERejectionSampler.d_le_semantic_post_rejection_view x s) E.
- rewrite /LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view.
  rewrite /LEFsProgrammingSurface.d_le_pre_fs_semantic_programming_view.
  rewrite dmap_comp /(\o).
  apply eq_dmap_in=> obs _ /=.
  rewrite /E.
  by rewrite (LEFsProgrammingSurface.le_fs_surrogate_transform_id obs).
have Hrej :
    dmap (LERejectionSampler.d_le_semantic_post_rejection_view x s) E =
    dmap (dunit (le_real_execution_observable x s)) E.
- rewrite /LERejectionSampler.d_le_semantic_post_rejection_view.
  rewrite (LERejectionSampler.d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE x s).
  rewrite dmap_comp /(\o).
  have -> :
      dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
        (fun reject =>
          E (LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable
            x s (le_real_execution_observable x s) reject)) =
      dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
        (fun _ => E (le_real_execution_observable x s)).
  - apply eq_dmap => reject /=.
    rewrite /E.
    by rewrite
      (le_distinguisher_event_on_semantic_rejection_branch_image_matches_base
        x s (le_real_execution_observable x s) reject D).
  rewrite (dmap_const_ll LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
    (E (le_real_execution_observable x s))
    LERejectionSampler.le_rejection_shadow_semantic_branch_choice_lossless).
  by rewrite dmap_dunit.
have Hpre_sim :
    dmap (dunit (le_real_execution_observable x s)) E =
    dmap (d_le_sim_view x s) E.
- have -> : d_le_sim_view x s = LEFsProgrammingSurface.d_le_post_fs_programmed_view x s.
    by rewrite /d_le_sim_view /LEFsProgrammingSurface.d_le_post_fs_programmed_view
      /LEFsProgrammingSurface.d_le_pre_fs_programming_view
      /LEFsProgrammingSurface.le_fs_surrogate_transform.
  rewrite /LEFsProgrammingSurface.d_le_post_fs_programmed_view.
  rewrite (LEFsProgrammingSurface.d_le_pre_fs_programming_view_dunit x s).
  rewrite dmap_comp /(\o).
  apply eq_dmap_in=> obs _ /=.
  rewrite /E.
  by rewrite (LEFsProgrammingSurface.le_fs_surrogate_transform_id obs).
have Hmapped :
    dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E =
    dmap (d_le_sim_view x s) E.
  by rewrite Hfs Hcollapse Hrej Hpre_sim.
rewrite /le_projected_sim_adv /le_projected_sim_adv_base /le_view_distinguish_pr.
  have Hmu :
    mu1 (dmap (d_le_sim_view x s) E) true =
    mu1 (dmap (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) E) true.
  - by rewrite Hmapped.
  have Hpred : ((pred1 true) \o E) = E.
  - apply fun_ext=> obs /=.
    rewrite /pred1 /(\o).
    by case: (E obs).
  move: Hmu.
  rewrite !dmap1E.
  by rewrite !Hpred.
qed.

lemma A_LE_semantic_projected_adv_matches_game_adv :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    Adv_G1_G2_LE x xms s D = le_semantic_view_distinguishing_adv x s D.
proof.
move=> x xms s D.
rewrite (A_Adv_G1_G2_LE_unfolds_to_projected_views x xms s D).
rewrite (A_LE_projected_real_adv_layout x xms s D).
rewrite (A_LE_semantic_projected_sim_adv_layout x s D).
by rewrite /le_semantic_view_distinguishing_adv.
qed.

lemma A_G1_to_G2_le_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D <= epsilon_le.
proof.
move=> x xms s D Hsetb Heps Hleeqv.
have Hhvzk := A_LE_HVZK_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_hvzk_transition_bound in Hhvzk.
have Hbridge := A_LE_game_bridge_consistency x xms s D.
rewrite /le_game_bridge_consistent in Hbridge.
by rewrite Hbridge; exact Hhvzk.
qed.

lemma A_G1_to_G2_le_semantic_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D <=
      LERejectionSampler.le_rejection_shadow_semantic_failure_probability x s +
      LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
proof.
move=> x xms s D Hsetb Heps Hleeqv.
have Hhvzk := A_LE_HVZK_semantic_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_semantic_view_advantage_bound_from_indistinguishability in Hhvzk.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hhvzk.
qed.

lemma A_G1_to_G2_le_semantic_owned_budget_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D <=
      BudgetParameters.epsilon_le_rej_semantic +
      BudgetParameters.epsilon_le_fs_semantic.
proof.
move=> x xms s D Hsetb Heps Hleeqv.
have Hhvzk := A_LE_HVZK_semantic_owned_budget_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_semantic_view_advantage_bound_from_owned_budget in Hhvzk.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hhvzk.
qed.

lemma A_G1_to_G2_le_semantic_umbrella_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D <= BudgetParameters.epsilon_le_semantic.
proof.
move=> x xms s D Hsetb Heps Hleeqv.
have Hhvzk := A_LE_HVZK_semantic_umbrella_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_semantic_view_advantage_bound_from_umbrella_budget in Hhvzk.
by rewrite (A_LE_semantic_projected_adv_matches_game_adv x xms s D); exact Hhvzk.
qed.
