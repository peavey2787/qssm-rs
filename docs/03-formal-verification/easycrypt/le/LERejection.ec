require import QssmTypes.
require import AllCore Distr.
require import Real.
require import SDist.
require import LESurface.

pred le_rejection_distribution_defined (x : qssm_public_input) (s : seed) =
  le_rejection_sampling_bound_ok.

pred le_rejection_acceptance_probability_bounded (x : qssm_public_input) (s : seed) =
  le_rejection_distribution_defined x s.

pred le_rejection_output_shape_preserved (x : qssm_public_input) (s : seed) =
  le_rejection_acceptance_probability_bounded x s.

pred le_rejection_witness_hiding_statistical_bound
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0%r <= epsilon_le /\ le_rejection_sampling_hiding_bound x s D.

(* Witness-hiding core at the rejection surrogate; currently aliases the same
   hiding predicate until rejection games refine this predicate. *)
pred le_rejection_witness_hiding_core (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_rejection_sampling_hiding_bound x s D.

axiom A_LE_rejection_distribution_defined :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_sampling_bound_ok =>
    le_rejection_distribution_defined x s.

axiom A_LE_rejection_acceptance_probability_bounded :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s.

axiom A_LE_rejection_output_shape_preserved :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s.

(* Rejection surrogate fixes the observable transcript shape (Set-B surface). *)
axiom A_LE_rejection_surrogate_preserves_shape :
  forall (obs : le_transcript_observable),
    le_commitment_coeffs (le_post_rejection_surrogate obs) = le_commitment_coeffs obs /\
    le_t_coeffs (le_post_rejection_surrogate obs) = le_t_coeffs obs /\
    le_z_coeffs (le_post_rejection_surrogate obs) = le_z_coeffs obs /\
    le_challenge_seed_obs (le_post_rejection_surrogate obs) = le_challenge_seed_obs obs /\
    le_programmed_query_digest_obs (le_post_rejection_surrogate obs) =
      le_programmed_query_digest_obs obs.

lemma L_LE_rejection_output_shape_implies_sampling_bound_ok :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_output_shape_preserved x s =>
    le_rejection_sampling_bound_ok.
proof.
move=> x s H.
by rewrite /le_rejection_output_shape_preserved /le_rejection_acceptance_probability_bounded
     /le_rejection_distribution_defined in H.
qed.

lemma L_LE_rejection_output_shape_implies_sampling_hiding_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_output_shape_preserved x s =>
    le_rejection_sampling_hiding_bound x s D.
proof.
move=> x s D H.
rewrite /le_rejection_sampling_hiding_bound.
exact (L_LE_rejection_output_shape_implies_sampling_bound_ok x s H).
qed.

lemma A_LE_rejection_surrogate_hides_witness :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_output_shape_preserved x s =>
    0%r <= epsilon_le =>
    le_rejection_witness_hiding_core x s D.
proof.
move=> x s D Hshape _.
by rewrite /le_rejection_witness_hiding_core;
  exact (L_LE_rejection_output_shape_implies_sampling_hiding_bound x s D Hshape).
qed.

lemma A_LE_rejection_witness_hiding_statistical_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_output_shape_preserved x s =>
    0%r <= epsilon_le =>
    le_rejection_witness_hiding_statistical_bound x s D.
proof.
move=> x s D Hshape Heps.
rewrite /le_rejection_witness_hiding_statistical_bound.
split; first exact Heps.
exact (L_LE_rejection_output_shape_implies_sampling_hiding_bound x s D Hshape).
qed.

lemma A_LE_rejection_sampling_hiding_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_bound_ok =>
    le_rejection_sampling_hiding_bound x s D.
proof.
move=> x s D Hrej.
have Hdef : le_rejection_distribution_defined x s.
  exact (A_LE_rejection_distribution_defined x s Hrej).
have Hacc : le_rejection_acceptance_probability_bounded x s.
  exact (A_LE_rejection_acceptance_probability_bounded x s Hdef).
have Hshape : le_rejection_output_shape_preserved x s.
  exact (A_LE_rejection_output_shape_preserved x s Hacc).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hw : le_rejection_witness_hiding_statistical_bound x s D.
  exact (A_LE_rejection_witness_hiding_statistical_bound x s D Hshape Heps).
by case: Hw.
qed.

(* Lower rejection-sampler target needed to eventually remove
   `A_LE_rejection_surrogate_sdist_bound` without renaming the quantitative debt.

   Intended theorem surface:

   lemma A_LE_rejection_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= (1%r / 2%r) * epsilon_le.

   This does not live at the current facade yet: `d_le_real_view` is still an
   abstract operator in `LESurface.ec`, and `d_le_post_rejection_view` is only
   the `dmap` push-forward of that abstract law through the abstract
   `le_post_rejection_surrogate`. A future lower sampler layer must either make
   those distributions concrete or prove an equivalent sampler coupling / sdist
   theorem from a concrete rejection execution surface. *)

axiom A_LE_rejection_surrogate_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s) (dmap (d_le_real_view x s) le_post_rejection_surrogate)
      <= (1%r / 2%r) * epsilon_le.

lemma A_LE_rejection_half_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s) (dmap (d_le_real_view x s) le_post_rejection_surrogate)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hrej Heps.
exact (A_LE_rejection_surrogate_sdist_bound x s D Hr Hs Hrej Heps).
qed.
