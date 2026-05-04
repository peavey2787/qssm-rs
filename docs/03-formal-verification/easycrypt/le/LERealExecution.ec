require import QssmTypes.
require import AllCore Distr.

(* Lower LE real-execution observable surface. The output carrier is concrete,
   while the field-producing execution hooks remain abstract until the LE
   execution semantics are refined further. *)
op le_real_execution_commitment_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector.

op le_real_execution_t_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector.

op le_real_execution_z_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector.

op le_real_execution_challenge_seed_obs
  (x : qssm_public_input) (s : seed) : digest.

op le_real_execution_programmed_query_digest_obs
  (x : qssm_public_input) (s : seed) : digest.

op le_real_execution_query_material
  (x : qssm_public_input) (s : seed) : le_query_material.

op le_real_execution_observable
  (x : qssm_public_input) (s : seed) : le_transcript_observable =
  {|
    leto_commitment_coeffs = le_real_execution_commitment_coeffs x s;
    leto_t_coeffs = le_real_execution_t_coeffs x s;
    leto_z_coeffs = le_real_execution_z_coeffs x s;
    leto_challenge_seed_obs = le_real_execution_challenge_seed_obs x s;
    leto_programmed_query_digest_obs =
      le_real_execution_programmed_query_digest_obs x s;
    leto_query_material = le_real_execution_query_material x s;
  |}.

op d_le_real_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dunit (le_real_execution_observable x s).