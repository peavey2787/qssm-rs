require import QssmTypes.
require import AllCore Distr.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LEFsProgrammingSurface.
require BudgetParameters.

(*---*) import RealOrder.

pred le_fs_query_surface_defined (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programmable_oracle_available (x : qssm_public_input) (s : seed) =
  le_fs_query_surface_defined x s.

pred le_fs_programming_preserves_transcript_shape (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programming_cost_bounded_by_epsilon_le
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0%r <= epsilon_le /\ le_fs_programming_hiding_bound x s D.

lemma A_LE_fs_query_surface_defined :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programming_bound_ok x s =>
    le_fs_query_surface_defined x s.
proof.
move=> x s H.
rewrite /le_fs_query_surface_defined.
by rewrite /le_fs_programming_bound_ok in H.
qed.

lemma A_LE_fs_programmable_oracle_available :
  forall (x : qssm_public_input) (s : seed),
    le_fs_query_surface_defined x s =>
    le_fs_programmable_oracle_available x s.
proof.
by move=> x s H; rewrite /le_fs_programmable_oracle_available.
qed.

lemma A_LE_fs_programming_preserves_transcript_shape :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programmable_oracle_available x s =>
    le_fs_programming_preserves_transcript_shape x s.
proof.
move=> x s H.
rewrite /le_fs_programming_preserves_transcript_shape.
by rewrite /le_fs_programmable_oracle_available /le_fs_query_surface_defined in H.
qed.

lemma A_LE_fs_programming_cost_bounded_by_epsilon_le :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_fs_programming_preserves_transcript_shape x s =>
    0%r <= epsilon_le =>
    le_fs_programming_cost_bounded_by_epsilon_le x s D.
proof.
move=> x s D Hshape Heps.
rewrite /le_fs_programming_cost_bounded_by_epsilon_le.
split; first exact Heps.
rewrite /le_fs_programming_hiding_bound /le_fs_programming_bound_ok.
by rewrite /le_fs_programming_preserves_transcript_shape in Hshape.
qed.

lemma A_LE_fs_programming_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_fs_programming_bound_ok x s =>
    le_fs_programming_hiding_bound x s D.
proof.
move=> x s D Hfs.
have Hsurf : le_fs_query_surface_defined x s.
  exact (A_LE_fs_query_surface_defined x s Hfs).
have Horacle : le_fs_programmable_oracle_available x s.
  exact (A_LE_fs_programmable_oracle_available x s Hsurf).
have Hshape : le_fs_programming_preserves_transcript_shape x s.
  exact (A_LE_fs_programming_preserves_transcript_shape x s Horacle).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hcost : le_fs_programming_cost_bounded_by_epsilon_le x s D.
  exact (A_LE_fs_programming_cost_bounded_by_epsilon_le x s D Hshape Heps).
by case: Hcost.
qed.

(* FS surrogate preserves the Set-B observable transcript shape (same surface as rejection). *)
lemma A_LE_fs_surrogate_preserves_shape :
  forall (obs : le_transcript_observable),
    le_commitment_coeffs (le_fs_view_surrogate obs) = le_commitment_coeffs obs /\
    le_t_coeffs (le_fs_view_surrogate obs) = le_t_coeffs obs /\
    le_z_coeffs (le_fs_view_surrogate obs) = le_z_coeffs obs /\
    le_challenge_seed_obs (le_fs_view_surrogate obs) = le_challenge_seed_obs obs /\
    le_programmed_query_digest_obs (le_fs_view_surrogate obs) =
      le_programmed_query_digest_obs obs.
proof.
exact le_fs_programming_preserves_shape_lower.
qed.

lemma A_LE_fs_programming_sampler_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_post_rejection_view x s)
      (dmap (d_le_post_rejection_view x s) le_fs_view_surrogate)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D _ _ _.
have Hshadow := LEFsProgrammingSurface.A_LE_fs_shadow_sdist_le_failure_probability x s.
have Hbudget := LEFsProgrammingSurface.A_LE_fs_shadow_failure_probability_le_budget x s.
have Hshadow_budget :
    sdist (LEFsProgrammingSurface.d_le_fs_shadow_pre_marginal x s)
      (LEFsProgrammingSurface.d_le_fs_shadow_post_marginal x s)
      <= BudgetParameters.epsilon_le_fs.
  exact (ler_trans _ _ _ Hshadow Hbudget).
move: Hshadow_budget.
rewrite LEFsProgrammingSurface.d_le_fs_shadow_pre_marginal_matches_post_rejection_view.
rewrite LEFsProgrammingSurface.d_le_fs_shadow_post_marginal_matches_programmed_view.
by [].
qed.

lemma A_LE_fs_surrogate_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_post_rejection_view x s)
        (dmap (d_le_post_rejection_view x s) le_fs_view_surrogate)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D Hr Hs Hfs.
exact (A_LE_fs_programming_sampler_sdist_le_budget x s D Hr Hs Hfs).
qed.

lemma A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s)
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
      <= LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s D _ _ _.
have Hshadow :=
  LEFsProgrammingSurface.A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass x s.
rewrite sdistC.
exact Hshadow.
qed.

lemma A_LE_fs_semantic_programming_sampler_sdist_le_owned_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (LEFsProgrammingSurface.d_le_post_fs_semantic_programmed_view x s)
      (LEFsProgrammingSurface.d_le_fs_shadow_semantic_post_marginal x s)
      <= BudgetParameters.epsilon_le_fs_semantic.
proof.
move=> x s D Hr Hs Hfs.
have Hmass :=
  A_LE_fs_semantic_programming_sampler_sdist_le_bad_branch_mass x s D Hr Hs Hfs.
exact (ler_trans _ _ _ Hmass
  LEFsProgrammingSurface.le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic).
qed.
