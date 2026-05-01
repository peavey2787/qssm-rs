require import AllCore List.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonTheorem.
require import SourceDistributions SourceTheorem MS LESurface LEModel LEHVZK.
require import GameTypes GameViews GameAdvantage.

pred le_game_bridge_consistent
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) =
  Adv_G1_G2_LE x xms s D = le_game_hop_adv x s D.

op le_view_of_game : game_view -> le_transcript_observable.

op le_real_view_from_G1
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) : le_transcript_observable =
  le_view_of_game (G1_ms_sim_le_real x xms s).

op le_sim_view_from_G2
  (x : qssm_public_input) (s : seed) : le_transcript_observable =
  le_view_of_game (G2_full_sim x s).

pred le_real_view_projects_from_G1 (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  le_view_of_game (G1_ms_sim_le_real x xms s) = le_real_view_from_G1 x xms s.

pred le_sim_view_projects_from_G2 (x : qssm_public_input) (s : seed) =
  le_view_of_game (G2_full_sim x s) = le_sim_view_from_G2 x s.

lemma A_G1_LE_view_constructor_correct :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    le_view_of_game (G1_ms_sim_le_real x xms s) = le_real_view_from_G1 x xms s.
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

(* Exact non-crypto interface boundary:
   generic game probability agrees with LE projected probability for G1/G2. *)
axiom A_game_pr_LE_projection_semantics :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_ms_sim_le_real x xms s) D = game_pr_le_projected true x s D /\
    game_pr (G2_full_sim x s) D = game_pr_le_projected false x s D.

lemma A_game_pr_on_G1_uses_LE_real_projection :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_ms_sim_le_real x xms s) D =
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
have [_ Hg2] := A_game_pr_LE_projection_semantics x witness s D.
rewrite Hg2 /game_pr_le_projected /=.
by [].
qed.

lemma A_game_pr_G1_LE_real_view_correct :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    game_pr (G1_ms_sim_le_real x xms s) D =
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
    game_pr (G1_ms_sim_le_real x xms s) D = le_projected_real_adv x xms s D.
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
rewrite (Adv_def (G1_ms_sim_le_real x xms s) (G2_full_sim x s) D).
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
