require import QssmTypes.
require import AllCore Distr.
require import Real.
require import SDist.
require import LESurface.
require import LEFsProgrammingSurface.

pred le_fs_query_surface_defined (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programmable_oracle_available (x : qssm_public_input) (s : seed) =
  le_fs_query_surface_defined x s.

pred le_fs_programming_preserves_transcript_shape (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programming_cost_bounded_by_epsilon_le
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0%r <= epsilon_le /\ le_fs_programming_hiding_bound x s D.

axiom A_LE_fs_query_surface_defined :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programming_bound_ok x s =>
    le_fs_query_surface_defined x s.

axiom A_LE_fs_programmable_oracle_available :
  forall (x : qssm_public_input) (s : seed),
    le_fs_query_surface_defined x s =>
    le_fs_programmable_oracle_available x s.

axiom A_LE_fs_programming_preserves_transcript_shape :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programmable_oracle_available x s =>
    le_fs_programming_preserves_transcript_shape x s.

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

axiom A_LE_fs_surrogate_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_post_rejection_view x s)
        (dmap (d_le_post_rejection_view x s) le_fs_view_surrogate)
      <= (1%r / 2%r) * epsilon_le.

lemma A_LE_fs_half_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_post_rejection_view x s)
        (dmap (d_le_post_rejection_view x s) le_fs_view_surrogate)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hfs Heps.
exact (A_LE_fs_surrogate_sdist_bound x s D Hr Hs Hfs Heps).
qed.
