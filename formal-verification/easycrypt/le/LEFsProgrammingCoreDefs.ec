require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LERejectionSampler.
require import LESurface.
require BudgetParameters.

(*---*) import RealOrder.

(* Pure FS-programming core definitions extracted from `LEFsProgrammingSurface.ec`.
   This file only owns the type/operator layer needed by the remaining proofs. *)

type le_fs_query_row = {
  lefsqr_challenge_seed : digest;
  lefsqr_programmed_query_digest : digest;
}.

type le_fs_visible_shell = {
  lefsvs_commitment_coeffs : coeff_vector;
  lefsvs_t_coeffs : coeff_vector;
  lefsvs_z_coeffs : coeff_vector;
  lefsvs_challenge_seed_obs : digest;
  lefsvs_programmed_query_digest_obs : digest;
  lefsvs_qssm_event_payload : qssm_event_payload;
}.

type le_fs_hidden_programming_state = {
  lefsps_visible_shell : le_fs_visible_shell;
  lefsps_query_material : le_query_material;
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

op le_fs_visible_shell_of_observable
  (obs : le_transcript_observable) : le_fs_visible_shell = {|
  lefsvs_commitment_coeffs = le_commitment_coeffs obs;
  lefsvs_t_coeffs = le_t_coeffs obs;
  lefsvs_z_coeffs = le_z_coeffs obs;
  lefsvs_challenge_seed_obs = le_challenge_seed_obs obs;
  lefsvs_programmed_query_digest_obs = le_programmed_query_digest_obs obs;
  lefsvs_qssm_event_payload = le_qssm_event_payload obs;
|}.

op le_fs_hidden_programming_state_of_observable
  (obs : le_transcript_observable) : le_fs_hidden_programming_state = {|
  lefsps_visible_shell = le_fs_visible_shell_of_observable obs;
  lefsps_query_material = le_fs_query_material_obs obs;
|}.

op le_fs_visible_shell_of_hidden_programming_state
  (st : le_fs_hidden_programming_state) : le_fs_visible_shell =
  st.`lefsps_visible_shell.

op le_fs_query_material_of_hidden_programming_state
  (st : le_fs_hidden_programming_state) : le_query_material =
  st.`lefsps_query_material.

op le_fs_observable_of_hidden_programming_state
  (st : le_fs_hidden_programming_state) : le_transcript_observable =
  {|
    leto_commitment_coeffs =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_commitment_coeffs;
    leto_t_coeffs =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_t_coeffs;
    leto_z_coeffs =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_z_coeffs;
    leto_challenge_seed_obs =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_challenge_seed_obs;
    leto_programmed_query_digest_obs =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_programmed_query_digest_obs;
    leto_query_material = le_fs_query_material_of_hidden_programming_state st;
    leto_qssm_event_payload =
      (le_fs_visible_shell_of_hidden_programming_state st).`lefsvs_qssm_event_payload;
  |}.

op le_fs_hidden_programming_state_update
  (st : le_fs_hidden_programming_state) : le_fs_hidden_programming_state = {|
  lefsps_visible_shell = le_fs_visible_shell_of_hidden_programming_state st;
  lefsps_query_material =
    le_fs_program_query_material (le_fs_query_material_of_hidden_programming_state st);
|}.

op le_fs_programmed_hidden_state_of_observable
  (obs : le_transcript_observable) : le_fs_hidden_programming_state =
  le_fs_hidden_programming_state_update
    (le_fs_hidden_programming_state_of_observable obs).

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

op d_le_pre_fs_semantic_programming_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LERejectionSampler.d_le_semantic_post_rejection_view x s.

op d_le_post_fs_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.

op d_le_post_fs_semantic_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_semantic_programming_view x s) le_fs_surrogate_transform.