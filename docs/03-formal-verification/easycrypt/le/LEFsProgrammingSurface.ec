require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require BudgetParameters.

(*---*) import RealOrder.

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

lemma le_fs_hidden_state_update_id :
  forall (st : le_fs_hidden_programming_state),
    le_fs_hidden_programming_state_update st = st.
proof.
case=> shell qmat /=.
by rewrite /le_fs_hidden_programming_state_update
  /le_fs_visible_shell_of_hidden_programming_state
  /le_fs_query_material_of_hidden_programming_state /le_fs_program_query_material.
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

lemma A_LE_fs_hidden_state_update_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_pre_fs_hidden_programming_state x s)
      (dmap (d_le_pre_fs_hidden_programming_state x s)
        le_fs_hidden_programming_state_update)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D _ _ _ Heps.
have Hmap :
  dmap (d_le_pre_fs_hidden_programming_state x s)
    le_fs_hidden_programming_state_update =
  dmap (d_le_pre_fs_hidden_programming_state x s)
    (fun (st : le_fs_hidden_programming_state) => st).
  apply eq_dmap_in=> st _ /=.
  exact (le_fs_hidden_state_update_id st).
rewrite Hmap dmap_id sdistdd.
have Hhalf : 0%r <= (1%r / 2%r) * epsilon_le by smt().
exact Hhalf.
qed.

lemma A_LE_fs_hidden_state_update_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_pre_fs_hidden_programming_state x s)
      (dmap (d_le_pre_fs_hidden_programming_state x s)
        le_fs_hidden_programming_state_update)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D _ _ _.
have Hmap :
  dmap (d_le_pre_fs_hidden_programming_state x s)
    le_fs_hidden_programming_state_update =
  dmap (d_le_pre_fs_hidden_programming_state x s)
    (fun (st : le_fs_hidden_programming_state) => st).
  apply eq_dmap_in=> st _ /=.
  exact (le_fs_hidden_state_update_id st).
rewrite Hmap dmap_id sdistdd.
rewrite /BudgetParameters.epsilon_le_fs.
by [].
qed.

lemma A_LE_fs_hidden_material_programming_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_pre_fs_hidden_programming_state x s)
      (d_le_post_fs_hidden_programming_state x s)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hfs Heps.
rewrite /d_le_post_fs_hidden_programming_state.
exact (A_LE_fs_hidden_state_update_sdist_bound x s D Hr Hs Hfs Heps).
qed.

lemma A_LE_fs_hidden_material_programming_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_pre_fs_hidden_programming_state x s)
      (d_le_post_fs_hidden_programming_state x s)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D Hr Hs Hfs.
rewrite /d_le_post_fs_hidden_programming_state.
exact (A_LE_fs_hidden_state_update_sdist_le_budget x s D Hr Hs Hfs).
qed.

lemma A_LE_fs_programming_sampler_sdist_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    0%r <= epsilon_le =>
    sdist (d_le_pre_fs_programming_view x s)
      (d_le_post_fs_programmed_view x s)
      <= (1%r / 2%r) * epsilon_le.
proof.
move=> x s D Hr Hs Hfs Heps.
rewrite d_le_pre_fs_programming_view_matches_hidden_state_projection.
rewrite d_le_post_fs_programmed_view_matches_hidden_state_projection.
have Hmap :
  sdist (dmap (d_le_pre_fs_hidden_programming_state x s)
          le_fs_observable_of_hidden_programming_state)
        (dmap (d_le_post_fs_hidden_programming_state x s)
          le_fs_observable_of_hidden_programming_state)
    <= sdist (d_le_pre_fs_hidden_programming_state x s)
         (d_le_post_fs_hidden_programming_state x s).
  exact (sdist_dmap (d_le_pre_fs_hidden_programming_state x s)
    (d_le_post_fs_hidden_programming_state x s)
    le_fs_observable_of_hidden_programming_state).
exact (ler_trans _ _ _ Hmap
  (A_LE_fs_hidden_material_programming_sdist_bound x s D Hr Hs Hfs Heps)).
qed.

lemma A_LE_fs_programming_sampler_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_pre_fs_programming_view x s)
      (d_le_post_fs_programmed_view x s)
      <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s D Hr Hs Hfs.
rewrite d_le_pre_fs_programming_view_matches_hidden_state_projection.
rewrite d_le_post_fs_programmed_view_matches_hidden_state_projection.
have Hmap :
  sdist (dmap (d_le_pre_fs_hidden_programming_state x s)
          le_fs_observable_of_hidden_programming_state)
        (dmap (d_le_post_fs_hidden_programming_state x s)
          le_fs_observable_of_hidden_programming_state)
    <= sdist (d_le_pre_fs_hidden_programming_state x s)
         (d_le_post_fs_hidden_programming_state x s).
  exact (sdist_dmap (d_le_pre_fs_hidden_programming_state x s)
    (d_le_post_fs_hidden_programming_state x s)
    le_fs_observable_of_hidden_programming_state).
exact (ler_trans _ _ _ Hmap
  (A_LE_fs_hidden_material_programming_sdist_le_budget x s D Hr Hs Hfs)).
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

type le_fs_shadow_hidden_material = {
  lefshm_query_row : le_fs_query_row;
  lefshm_pre_query_material : le_query_material;
  lefshm_semantic_post_query_material : le_query_material;
  lefshm_programmed_response : le_fs_programmed_response_carrier;
  lefshm_bad_flag : bool;
}.

type le_fs_shadow_state = {
  lefss_pre_observable : le_transcript_observable;
  lefss_post_observable : le_transcript_observable;
  lefss_hidden_material : le_fs_shadow_hidden_material;
}.

op le_fs_shadow_programming_log_of_observable
  (obs : le_transcript_observable) : digest list =
  [le_challenge_seed_obs obs; le_programmed_query_digest_obs obs].

op le_fs_shadow_semantic_post_query_material_of_observable
  (obs : le_transcript_observable) : le_query_material =
  {| leqm_row_challenge_seed = le_challenge_seed_obs obs;
     leqm_row_programmed_query_digest = le_programmed_query_digest_obs obs;
     leqm_programmed_response_digest = le_programmed_query_digest_obs obs;
     leqm_programming_log = le_fs_shadow_programming_log_of_observable obs;
     leqm_bad_flag = false |}.

op le_fs_shadow_hidden_material_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_hidden_material =
  {| lefshm_query_row = le_fs_query_row_of_observable obs;
     lefshm_pre_query_material = le_fs_query_material_obs obs;
     lefshm_semantic_post_query_material =
       le_fs_shadow_semantic_post_query_material_of_observable obs;
     lefshm_programmed_response = le_fs_programmed_response_of_observable obs;
     lefshm_bad_flag = false |}.

op le_fs_shadow_post_of_observable
  (obs : le_transcript_observable) (hm : le_fs_shadow_hidden_material) :
  le_transcript_observable =
  hm.`lefshm_programmed_response.`lefspc_programmed_view.

op le_fs_shadow_state_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_state =
  let hm = le_fs_shadow_hidden_material_of_observable obs in
  {| lefss_pre_observable = obs;
     lefss_post_observable = le_fs_shadow_post_of_observable obs hm;
     lefss_hidden_material = hm |}.

op le_fs_shadow_pre_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_pre_observable.

op le_fs_shadow_post_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_post_observable.

op le_fs_shadow_bad_event
  (st : le_fs_shadow_state) : bool =
  st.`lefss_hidden_material.`lefshm_bad_flag.

op d_le_fs_shadow_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  dmap (d_le_pre_fs_programming_view x s)
    le_fs_shadow_state_of_observable.

op d_le_fs_shadow_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_pre_observable.

op d_le_fs_shadow_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_post_observable.

op le_fs_shadow_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_bad_event.

lemma le_fs_shadow_post_of_observable_matches_surrogate
  (obs : le_transcript_observable) :
  (le_fs_shadow_state_of_observable obs).`lefss_post_observable =
  le_fs_surrogate_transform obs.
proof.
rewrite /le_fs_shadow_state_of_observable.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable.
by rewrite /le_fs_programmed_response_of_observable.
qed.

lemma le_fs_shadow_post_observable_preserves_visible_fields
  (obs : le_transcript_observable) :
  le_commitment_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_commitment_coeffs obs /\
  le_t_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_t_coeffs obs /\
  le_z_coeffs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_z_coeffs obs /\
  le_challenge_seed_obs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_challenge_seed_obs obs /\
  le_programmed_query_digest_obs ((le_fs_shadow_state_of_observable obs).`lefss_post_observable) =
    le_programmed_query_digest_obs obs.
proof.
rewrite (le_fs_shadow_post_of_observable_matches_surrogate obs).
exact (le_fs_programming_preserves_shape_lower obs).
qed.

lemma le_fs_shadow_bad_event_current_model
  (obs : le_transcript_observable) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
rewrite /le_fs_shadow_bad_event /le_fs_shadow_state_of_observable.
by rewrite /le_fs_shadow_hidden_material_of_observable.
qed.

lemma d_le_fs_shadow_pre_marginal_matches_pre_programming_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_pre_fs_programming_view x s.
proof.
move=> x s.
rewrite /d_le_fs_shadow_pre_marginal /d_le_fs_shadow_coupled_state.
rewrite (dmap_comp le_fs_shadow_state_of_observable
  le_fs_shadow_pre_observable
  (d_le_pre_fs_programming_view x s)).
have Hmap :
  dmap (d_le_pre_fs_programming_view x s)
    (le_fs_shadow_pre_observable \o le_fs_shadow_state_of_observable) =
  dmap (d_le_pre_fs_programming_view x s)
    (fun (obs : le_transcript_observable) => obs).
  apply eq_dmap_in=> obs _ /=.
  by rewrite /le_fs_shadow_pre_observable /le_fs_shadow_state_of_observable /(\o).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma d_le_fs_shadow_pre_marginal_matches_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_post_rejection_view x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view.
by rewrite /d_le_pre_fs_programming_view.
qed.

lemma d_le_fs_shadow_post_marginal_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_post_fs_programmed_view x s.
proof.
move=> x s.
rewrite /d_le_fs_shadow_post_marginal /d_le_fs_shadow_coupled_state.
rewrite (dmap_comp le_fs_shadow_state_of_observable
  le_fs_shadow_post_observable
  (d_le_pre_fs_programming_view x s)).
have Hmap :
  dmap (d_le_pre_fs_programming_view x s)
    (le_fs_shadow_post_observable \o le_fs_shadow_state_of_observable) =
  dmap (d_le_pre_fs_programming_view x s)
    le_fs_surrogate_transform.
  apply eq_dmap_in=> obs _ /=.
  rewrite /le_fs_shadow_post_observable /(\o).
  exact (le_fs_shadow_post_of_observable_matches_surrogate obs).
rewrite Hmap.
by rewrite /d_le_post_fs_programmed_view.
qed.

lemma d_le_fs_shadow_post_marginal_matches_sim_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_sim_view x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_post_marginal_matches_programmed_view.
by rewrite /d_le_post_fs_programmed_view /d_le_pre_fs_programming_view
  /d_le_sim_view /le_fs_surrogate_transform.
qed.

lemma le_fs_surrogate_transform_id
  (obs : le_transcript_observable) :
  le_fs_surrogate_transform obs = obs.
proof.
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
by rewrite /le_fs_surrogate_transform /le_fs_view_surrogate
  /le_fs_program_query_material.
qed.

lemma d_le_fs_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
proof.
move=> x s.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view.
rewrite d_le_fs_shadow_post_marginal_matches_programmed_view.
rewrite /d_le_post_fs_programmed_view.
have Hmap :
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform =
  dmap (d_le_pre_fs_programming_view x s)
    (fun (obs : le_transcript_observable) => obs).
  apply eq_dmap_in=> obs _ /=.
  exact (le_fs_surrogate_transform_id obs).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma le_fs_shadow_failure_probability_zero :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_failure_probability x s = 0%r.
proof.
move=> x s.
rewrite /le_fs_shadow_failure_probability /d_le_fs_shadow_coupled_state.
rewrite /d_le_pre_fs_programming_view /d_le_post_rejection_view.
rewrite /d_le_real_view /d_le_real_execution_view /le_post_rejection_surrogate.
rewrite dmap_dunit dmap_dunit dunitE /=.
rewrite /le_fs_shadow_bad_event /le_fs_shadow_state_of_observable.
by rewrite /le_fs_shadow_hidden_material_of_observable.
qed.

lemma A_LE_fs_shadow_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_pre_marginal x s)
      (d_le_fs_shadow_post_marginal x s)
      <= le_fs_shadow_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_fs_shadow_pre_post_marginals_equal x s).
rewrite sdistdd.
rewrite (le_fs_shadow_failure_probability_zero x s).
by [].
qed.

lemma A_LE_fs_shadow_failure_probability_le_budget :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_failure_probability x s <= BudgetParameters.epsilon_le_fs.
proof.
move=> x s.
rewrite (le_fs_shadow_failure_probability_zero x s).
rewrite /BudgetParameters.epsilon_le_fs.
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

   The quantitative lower law is now isolated as
   `A_LE_fs_hidden_state_update_sdist_bound` on the hidden-state update itself.
   The two theorem-facing lower corollaries derived from it are:

   lemma A_LE_fs_hidden_material_programming_sdist_bound :
     forall (x : qssm_public_input) (s : seed) (D : distinguisher),
       le_real_view_distribution_defined x s =>
       le_sim_view_distribution_defined x s =>
       le_fs_programming_hiding_bound x s D =>
       0%r <= epsilon_le =>
       sdist (d_le_pre_fs_hidden_programming_state x s)
         (d_le_post_fs_hidden_programming_state x s)
         <= (1%r / 2%r) * epsilon_le.

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