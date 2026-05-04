require import QssmTypes.
require import AllCore Distr.
require import SDist.
require import LESurface.

(* Lower execution-facing rejection sampler boundary below `LERejection.ec`.
   This file introduces the sampler surface needed to eventually discharge the
   rejection-side sdist theorem without adding a new quantitative axiom. *)

op d_le_rejection_real_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_real_view x s.

op le_rejection_transform
  (obs : le_transcript_observable) : le_transcript_observable =
  le_post_rejection_surrogate obs.

op d_le_rejection_post_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_real_execution_view x s) le_rejection_transform.

lemma le_real_view_matches_rejection_execution :
  forall (x : qssm_public_input) (s : seed),
    d_le_real_view x s = d_le_rejection_real_execution_view x s.
proof.
by move=> x s; rewrite /d_le_rejection_real_execution_view.
qed.

lemma le_post_rejection_view_matches_execution_transform :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_rejection_view x s = d_le_rejection_post_execution_view x s.
proof.
move=> x s.
rewrite /d_le_post_rejection_view /d_le_rejection_post_execution_view.
rewrite /d_le_rejection_real_execution_view /le_rejection_transform.
by [].
qed.

(* Intended bridge targets from the lower rejection sampler surface to the
   current LE facade.

   lemma A_LE_rejection_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= (1%r / 2%r) * epsilon_le.

   The two bridge lemmas keep the theorem-facing statement on the current
   facade, while the lower sampler surface here carries the concrete execution
   law and transform that must eventually justify it. *)