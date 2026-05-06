require import QssmTypes.
require import AllCore Distr.
require import Real.
require import Ring.
require import SDist.
require import LESurface.
require import LERejectionSampler.
require BudgetParameters.

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

lemma A_LE_rejection_distribution_defined :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_sampling_bound_ok =>
    le_rejection_distribution_defined x s.
proof.
by move=> x s H; rewrite /le_rejection_distribution_defined.
qed.

lemma A_LE_rejection_acceptance_probability_bounded :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s.
proof.
by move=> x s H; rewrite /le_rejection_acceptance_probability_bounded.
qed.

lemma A_LE_rejection_output_shape_preserved :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s.
proof.
by move=> x s H; rewrite /le_rejection_output_shape_preserved.
qed.

(* Rejection surrogate fixes the observable transcript shape (Set-B surface). *)
lemma A_LE_rejection_surrogate_preserves_shape :
  forall (obs : le_transcript_observable),
    le_commitment_coeffs (le_post_rejection_surrogate obs) = le_commitment_coeffs obs /\
    le_t_coeffs (le_post_rejection_surrogate obs) = le_t_coeffs obs /\
    le_z_coeffs (le_post_rejection_surrogate obs) = le_z_coeffs obs /\
    le_challenge_seed_obs (le_post_rejection_surrogate obs) = le_challenge_seed_obs obs /\
    le_programmed_query_digest_obs (le_post_rejection_surrogate obs) =
      le_programmed_query_digest_obs obs.
proof.
by move=> obs; rewrite /le_post_rejection_surrogate.
qed.

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

   `LERejectionSampler.ec` now also exposes a shadow coupled-state lane beside
   the active exact-zero path:

   - `le_rejection_shadow_state`
   - `d_le_rejection_shadow_coupled_state`
   - `d_le_rejection_shadow_pre_marginal`
   - `d_le_rejection_shadow_post_marginal`
   - `le_rejection_shadow_failure_probability`

  Those names are now the lower insertion point for both the exact-zero
  rejection budget `epsilon_le_rej` and the parallel semantic rejection
  budget `epsilon_le_rej_semantic`. The intended shadow-lane theorems are:

   lemma A_LE_rejection_shadow_sdist_le_failure_probability :
     forall (x : qssm_public_input) (s : seed),
       sdist (d_le_rejection_shadow_pre_marginal x s)
             (d_le_rejection_shadow_post_marginal x s)
         <= le_rejection_shadow_failure_probability x s.

   lemma A_LE_rejection_shadow_failure_probability_le_budget :
     forall (x : qssm_public_input) (s : seed),
       le_rejection_shadow_failure_probability x s <= epsilon_le_rej.

   lemma A_LE_rejection_shadow_failure_probability_le_semantic_budget :
     forall (x : qssm_public_input) (s : seed),
       le_rejection_shadow_failure_probability x s <= epsilon_le_rej_semantic.

   Intended theorem surface:

   lemma A_LE_rejection_sampler_semantic_sdist_le_failure_probability :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= le_rejection_shadow_failure_probability x s.

   lemma A_LE_rejection_sampler_semantic_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= epsilon_le_rej_semantic.

   lemma A_LE_rejection_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= epsilon_le_rej.

   The lower bridge names now live in `LERejectionSampler.ec`. At the current
   abstraction boundary this theorem can be repackaged from the existing
   quantitative axiom surface, but that does not reduce the remaining axiom:
   `d_le_real_view` and `le_post_rejection_surrogate` are still abstract in
   `LESurface.ec`, so a future lower sampler layer must still make those
   distributions concrete or prove an equivalent sampler coupling / sdist
   theorem from a concrete rejection execution surface. *)

lemma A_LE_rejection_shadow_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_shadow_pre_marginal x s)
      (d_le_rejection_shadow_post_marginal x s)
      <= le_rejection_shadow_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_rejection_shadow_pre_post_marginals_equal x s).
rewrite sdistdd.
rewrite (le_rejection_shadow_failure_probability_zero x s).
by [].
qed.

lemma A_LE_rejection_shadow_failure_probability_le_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_failure_probability x s <= BudgetParameters.epsilon_le_rej.
proof.
move=> x s.
rewrite (le_rejection_shadow_failure_probability_zero x s).
rewrite /BudgetParameters.epsilon_le_rej.
by [].
qed.

lemma A_LE_rejection_sampler_semantic_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
      <= le_rejection_shadow_failure_probability x s.
proof.
move=> x s _ _ _ _.
rewrite -(d_le_rejection_shadow_pre_marginal_matches_real_view x s).
rewrite -(d_le_rejection_shadow_post_marginal_matches_post_rejection_view x s).
exact (A_LE_rejection_shadow_sdist_le_failure_probability x s).
qed.

lemma A_LE_rejection_sampler_semantic_sdist_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
      <= BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s Hr Hdef Hacc Hshape.
have Hshadow :=
  A_LE_rejection_sampler_semantic_sdist_le_failure_probability x s Hr Hdef Hacc Hshape.
have Hbudget := A_LE_rejection_shadow_failure_probability_le_semantic_budget x s.
by smt().
qed.

lemma A_LE_rejection_surrogate_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_real_view x s) (dmap (d_le_real_view x s) le_post_rejection_surrogate)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D _ _ _ Heps.
rewrite /le_post_rejection_surrogate dmap_id sdistdd.
have Hhalf : 0%r <= (1%r / 2%r) * epsilon_le by smt().
exact Hhalf.
qed.

lemma A_LE_rejection_sampler_sdist_bound :
  forall (x : qssm_public_input) (s : seed),
    le_real_view_distribution_defined x s =>
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s =>
    sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
      <= BudgetParameters.epsilon_le_rej.
proof.
move=> x s Hr Hdef Hacc Hshape.
have Hshadow :=
  A_LE_rejection_sampler_semantic_sdist_le_failure_probability x s Hr Hdef Hacc Hshape.
have Hbudget := A_LE_rejection_shadow_failure_probability_le_budget x s.
by smt().
qed.
