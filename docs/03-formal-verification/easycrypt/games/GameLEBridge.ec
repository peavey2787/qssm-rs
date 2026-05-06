require import AllCore List Distr.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem.
require BudgetParameters.
require import SourceDistributions SourceTheorem MS LERealExecution LESurface LEModel LERejectionSampler LEStatisticalDistance LEHVZK.
require import LEFsProgrammingSurface.
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
  rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_programmed_view_of_observable.
  rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_post_observable.
  rewrite /LEFsProgrammingSurface.le_fs_shadow_hidden_material_of_observable_branch.
  rewrite /LEFsProgrammingSurface.le_fs_programmed_response_of_observable.
  rewrite /LEFsProgrammingSurface.le_fs_surrogate_transform.
  rewrite /le_distinguisher_event /le_qssm_event_payload /le_fs_view_surrogate /=.
  by [].
by rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
  /LEFsProgrammingSurface.le_fs_surrogate_transform.
qed.

lemma A_LE_semantic_projected_sim_adv_layout :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_projected_sim_adv x s D =
      le_view_distinguish_pr
        (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s) D.
proof.
move=> x s D.
rewrite /le_projected_sim_adv /le_projected_sim_adv_base /le_view_distinguish_pr.
have -> : d_le_sim_view x s = LEFsProgrammingSurface.d_le_post_fs_programmed_view x s.
  by rewrite /d_le_sim_view /LEFsProgrammingSurface.d_le_post_fs_programmed_view
    /LEFsProgrammingSurface.d_le_pre_fs_programming_view
    /LEFsProgrammingSurface.le_fs_surrogate_transform.
rewrite (LEFsProgrammingSurface.d_le_post_fs_programmed_view_fixed_branch_imageE x s).
rewrite (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal_fixed_branch_imageE x s).
pose F := fun bad =>
  LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
    (le_real_execution_observable x s) bad.
pose P := fun bad => le_distinguisher_event D (F bad).
rewrite dmapE.
rewrite dmapE.
have Hconst : forall bad, P bad = P false.
  move=> bad.
  rewrite /P /F.
  by rewrite (le_distinguisher_event_on_semantic_branch_image_matches_surrogate
    (le_real_execution_observable x s) bad D)
    (le_distinguisher_event_on_semantic_branch_image_matches_surrogate
    (le_real_execution_observable x s) false D).
have Hleft :
    mu (dunit false) P = mu (dunit false) (fun (_ : bool) => P false).
  apply/mu_eq=> bad /=.
  exact (Hconst bad).
have Hright :
    mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice P =
    mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice (fun (_ : bool) => P false).
  apply/mu_eq=> bad /=.
  exact (Hconst bad).
rewrite Hleft Hright.
case: (P false).
- have HleftT :
      mu (dunit false) (fun (_ : bool) => true) = mu (dunit false) predT.
    apply/mu_eq=> bad /=.
    by [].
  have HrightT :
      mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice (fun (_ : bool) => true) =
      mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice predT.
    apply/mu_eq=> bad /=.
    by [].
  have Hw : weight LEFsProgrammingSurface.d_le_fs_shadow_branch_choice = 1%r.
    exact (is_losslessP _ LEFsProgrammingSurface.le_fs_shadow_branch_choice_lossless).
  rewrite HleftT HrightT.
  by rewrite dunit_ll /weight Hw.
have Hleft0 :
    mu (dunit false) (fun (_ : bool) => false) = mu (dunit false) pred0.
  apply/mu_eq=> bad /=.
  by [].
have Hright0 :
    mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice (fun (_ : bool) => false) =
    mu LEFsProgrammingSurface.d_le_fs_shadow_branch_choice pred0.
  apply/mu_eq=> bad /=.
  by [].
by rewrite Hleft0 Hright0 !mu0.
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
