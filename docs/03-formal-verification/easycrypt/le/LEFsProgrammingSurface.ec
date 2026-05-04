require import QssmTypes.
require import AllCore Distr.
require import SDist.
require import LESurface.

(* Lower execution-facing FS-programming boundary below `LEFsProgramming.ec`.
   This file introduces the concrete lower names needed to eventually discharge
   the FS-side sdist theorem without collapsing FS programming to the identity. *)

type le_fs_query_row = {
  lefsqr_challenge_seed : digest;
  lefsqr_programmed_query_digest : digest;
}.

type le_fs_programmed_response_carrier = {
  lefspc_query_row : le_fs_query_row;
  lefspc_programmed_view : le_transcript_observable;
}.

op le_fs_query_row_of_observable
  (obs : le_transcript_observable) : le_fs_query_row = {|
  lefsqr_challenge_seed = le_challenge_seed_obs obs;
  lefsqr_programmed_query_digest = le_programmed_query_digest_obs obs;
|}.

op le_fs_surrogate_transform
  (obs : le_transcript_observable) : le_transcript_observable =
  le_fs_view_surrogate obs.

op le_fs_programmed_response_of_observable
  (obs : le_transcript_observable) : le_fs_programmed_response_carrier = {|
  lefspc_query_row = le_fs_query_row_of_observable obs;
  lefspc_programmed_view = le_fs_surrogate_transform obs;
|}.

op d_le_pre_fs_programming_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_post_rejection_view x s.

op d_le_post_fs_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.

op d_le_fs_programmed_response_carrier
  (x : qssm_public_input) (s : seed) : le_fs_programmed_response_carrier distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_programmed_response_of_observable.

lemma le_fs_surrogate_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_programmed_view x s =
      dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.
proof.
by move=> x s; rewrite /d_le_post_fs_programmed_view.
qed.

(* Intended bridge/analysis targets for the lower FS-programming surface.

   The first bridge fact above is definitional. The next lower shape theorem is
   still blocked here because `le_fs_surrogate_transform` only unfolds to the
   abstract facade operator `le_fs_view_surrogate`; below `LEFsProgramming.ec`
   there is not yet any concrete constructor or fieldwise equality theorem for
   that transform on `le_transcript_observable`.

   lemma le_fs_query_surface_sound :
     forall (obs : le_transcript_observable),
       lefsqr_challenge_seed (le_fs_query_row_of_observable obs) =
         le_challenge_seed_obs obs /\
       lefsqr_programmed_query_digest (le_fs_query_row_of_observable obs) =
         le_programmed_query_digest_obs obs.

   lemma le_fs_programming_preserves_shape_lower :
     forall (obs : le_transcript_observable),
       le_commitment_coeffs (le_fs_surrogate_transform obs) = le_commitment_coeffs obs /\
       le_t_coeffs (le_fs_surrogate_transform obs) = le_t_coeffs obs /\
       le_z_coeffs (le_fs_surrogate_transform obs) = le_z_coeffs obs /\
       le_challenge_seed_obs (le_fs_surrogate_transform obs) = le_challenge_seed_obs obs /\
       le_programmed_query_digest_obs (le_fs_surrogate_transform obs) =
         le_programmed_query_digest_obs obs.

   lemma A_LE_fs_programming_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed) (D : distinguisher),
       le_real_view_distribution_defined x s =>
       le_sim_view_distribution_defined x s =>
       le_fs_programming_hiding_bound x s D =>
       0%r <= epsilon_le =>
       sdist (d_le_pre_fs_programming_view x s)
         (d_le_post_fs_programmed_view x s)
         <= (1%r / 2%r) * epsilon_le.

   The point of this file is to expose the FS-programming lane below
   `LEFsProgramming.ec` without forcing `LESurface.ec` to import a higher
   module or collapsing the FS surrogate to the identity on the current
   abstract carrier. *)