require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERejectionSampler.
require import LESurface.
require import LEFsProgrammingCoreDefs.
require BudgetParameters.

(*---*) import RealOrder.

(* Lower hidden-state reconstruction / projection lane extracted from
   `LEFsProgrammingSurface.ec`. This file owns the concrete hidden-state
   distributions and the lower quantitative proofs over them. *)

op d_le_pre_fs_hidden_programming_state
  (x : qssm_public_input) (s : seed) : le_fs_hidden_programming_state distr =
  dmap (d_le_pre_fs_programming_view x s)
    le_fs_hidden_programming_state_of_observable.

op d_le_post_fs_hidden_programming_state
  (x : qssm_public_input) (s : seed) : le_fs_hidden_programming_state distr =
  dmap (d_le_pre_fs_hidden_programming_state x s)
    le_fs_hidden_programming_state_update.

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