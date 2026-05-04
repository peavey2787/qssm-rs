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

type le_fs_visible_shell = {
  lefsvs_commitment_coeffs : coeff_vector;
  lefsvs_t_coeffs : coeff_vector;
  lefsvs_z_coeffs : coeff_vector;
  lefsvs_challenge_seed_obs : digest;
  lefsvs_programmed_query_digest_obs : digest;
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

op d_le_post_fs_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.

op d_le_pre_fs_hidden_programming_state
  (x : qssm_public_input) (s : seed) : le_fs_hidden_programming_state distr =
  dmap (d_le_pre_fs_programming_view x s)
    le_fs_hidden_programming_state_of_observable.

op d_le_post_fs_hidden_programming_state
  (x : qssm_public_input) (s : seed) : le_fs_hidden_programming_state distr =
  dmap (d_le_pre_fs_hidden_programming_state x s)
    le_fs_hidden_programming_state_update.

op d_le_fs_programmed_response_carrier
  (x : qssm_public_input) (s : seed) : le_fs_programmed_response_carrier distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_programmed_response_of_observable.

lemma le_fs_hidden_state_reconstructs_observable :
  forall (obs : le_transcript_observable),
    le_fs_observable_of_hidden_programming_state
      (le_fs_hidden_programming_state_of_observable obs) = obs.
proof.
case=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat /=.
by rewrite /le_fs_observable_of_hidden_programming_state
  /le_fs_hidden_programming_state_of_observable /le_fs_visible_shell_of_observable
  /le_fs_visible_shell_of_hidden_programming_state
  /le_fs_query_material_of_hidden_programming_state
  /le_commitment_coeffs /le_t_coeffs /le_z_coeffs
  /le_challenge_seed_obs /le_programmed_query_digest_obs /le_fs_query_material_obs.
qed.

lemma le_fs_hidden_state_update_preserves_visible_shell :
  forall (st : le_fs_hidden_programming_state),
    le_fs_visible_shell_of_hidden_programming_state
      (le_fs_hidden_programming_state_update st) =
    le_fs_visible_shell_of_hidden_programming_state st.
proof.
by move=> st; rewrite /le_fs_visible_shell_of_hidden_programming_state
  /le_fs_hidden_programming_state_update.
qed.

lemma le_fs_hidden_state_update_matches_surrogate :
  forall (obs : le_transcript_observable),
    le_fs_observable_of_hidden_programming_state
      (le_fs_hidden_programming_state_update
        (le_fs_hidden_programming_state_of_observable obs)) =
    le_fs_surrogate_transform obs.
proof.
move=> obs.
rewrite /le_fs_observable_of_hidden_programming_state.
rewrite /le_fs_hidden_programming_state_update.
rewrite /le_fs_hidden_programming_state_of_observable /le_fs_visible_shell_of_observable.
rewrite /le_fs_visible_shell_of_hidden_programming_state.
rewrite /le_fs_query_material_of_hidden_programming_state.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs /le_fs_query_material_obs.
by [].
qed.

lemma d_le_pre_fs_programming_view_matches_hidden_state_projection :
  forall (x : qssm_public_input) (s : seed),
    d_le_pre_fs_programming_view x s =
      dmap (d_le_pre_fs_hidden_programming_state x s)
        le_fs_observable_of_hidden_programming_state.
proof.
move=> x s.
rewrite /d_le_pre_fs_hidden_programming_state.
rewrite (dmap_comp le_fs_hidden_programming_state_of_observable
  le_fs_observable_of_hidden_programming_state
  (d_le_pre_fs_programming_view x s)).
have Hmap :
  dmap (d_le_pre_fs_programming_view x s)
    (le_fs_observable_of_hidden_programming_state
      \o le_fs_hidden_programming_state_of_observable) =
  dmap (d_le_pre_fs_programming_view x s)
    (fun (obs : le_transcript_observable) => obs).
  apply eq_dmap_in=> obs _ /=.
  exact (le_fs_hidden_state_reconstructs_observable obs).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma d_le_post_fs_hidden_state_matches_programmed_hidden_state :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_hidden_programming_state x s =
      dmap (d_le_pre_fs_programming_view x s)
        le_fs_programmed_hidden_state_of_observable.
proof.
move=> x s.
rewrite /d_le_post_fs_hidden_programming_state /d_le_pre_fs_hidden_programming_state.
rewrite (dmap_comp le_fs_hidden_programming_state_of_observable
  le_fs_hidden_programming_state_update
  (d_le_pre_fs_programming_view x s)).
apply eq_dmap_in=> obs _ /=.
by rewrite /le_fs_programmed_hidden_state_of_observable.
qed.

lemma d_le_post_fs_programmed_view_matches_hidden_state_projection :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_programmed_view x s =
      dmap (d_le_post_fs_hidden_programming_state x s)
        le_fs_observable_of_hidden_programming_state.
proof.
move=> x s.
rewrite /d_le_post_fs_programmed_view.
rewrite d_le_post_fs_hidden_state_matches_programmed_hidden_state.
rewrite (dmap_comp le_fs_programmed_hidden_state_of_observable
  le_fs_observable_of_hidden_programming_state
  (d_le_pre_fs_programming_view x s)).
apply eq_dmap_in=> obs _ /=.
rewrite /(\o).
rewrite /le_fs_programmed_hidden_state_of_observable.
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat /=.
by rewrite /le_fs_observable_of_hidden_programming_state
  /le_fs_hidden_programming_state_update
  /le_fs_hidden_programming_state_of_observable /le_fs_visible_shell_of_observable
  /le_fs_visible_shell_of_hidden_programming_state
  /le_fs_query_material_of_hidden_programming_state
  /le_fs_surrogate_transform /le_fs_view_surrogate
  /le_commitment_coeffs /le_t_coeffs /le_z_coeffs
  /le_challenge_seed_obs /le_programmed_query_digest_obs /le_fs_query_material_obs.
qed.

lemma le_fs_surrogate_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_programmed_view x s =
      dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.
proof.
by move=> x s; rewrite /d_le_post_fs_programmed_view.
qed.

lemma le_fs_programming_preserves_shape_lower :
  forall (obs : le_transcript_observable),
    le_commitment_coeffs (le_fs_surrogate_transform obs) = le_commitment_coeffs obs /\
    le_t_coeffs (le_fs_surrogate_transform obs) = le_t_coeffs obs /\
    le_z_coeffs (le_fs_surrogate_transform obs) = le_z_coeffs obs /\
    le_challenge_seed_obs (le_fs_surrogate_transform obs) = le_challenge_seed_obs obs /\
    le_programmed_query_digest_obs (le_fs_surrogate_transform obs) =
      le_programmed_query_digest_obs obs.
proof.
move=> obs.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs.
by [].
qed.

(* Intended bridge/analysis targets for the lower FS-programming surface.

   The first bridge facts above are definitional. The lower shape theorem is
   also now definitional because `le_transcript_observable` carries a hidden
   FS-programming field and `le_fs_view_surrogate` updates only that hidden
   component while preserving the five theorem-facing observable fields.

   The new joint-state carrier `le_fs_hidden_programming_state` isolates the
   visible LE shell from the hidden `le_query_material`, with the post-FS state
   distribution obtained by mapping the pre-FS state through
   `le_fs_hidden_programming_state_update`.

   lemma le_fs_query_surface_sound :
     forall (obs : le_transcript_observable),
       lefsqr_challenge_seed (le_fs_query_row_of_observable obs) =
         le_challenge_seed_obs obs /\
       lefsqr_programmed_query_digest (le_fs_query_row_of_observable obs) =
         le_programmed_query_digest_obs obs.

   lemma A_LE_fs_hidden_material_programming_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_fs_query_surface_defined x s =>
       le_fs_programmable_oracle_available x s =>
       le_fs_programming_preserves_transcript_shape x s =>
       0%r <= epsilon_le =>
       sdist (d_le_pre_fs_hidden_programming_state x s)
         (d_le_post_fs_hidden_programming_state x s)
         <= (1%r / 2%r) * epsilon_le.

   The point of this file is to expose the FS-programming lane below
   `LEFsProgramming.ec` without forcing `LESurface.ec` to import a higher
   module or collapsing the FS surrogate to the identity on the current
   abstract carrier. *)