require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LERejectionSampler.
require import LESurface.
require LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require import LEFsProgrammingCoupledState.
require import LEFsProgrammingMarginalHelpers.
require import LEFsProgrammingMarginalStateFacts.
require import LEFsProgrammingMarginals.
require import LEFsProgrammingSupportImages.
require import LEFsProgrammingPostMarginal.
require import LEFsProgrammingFailureProbability.
require BudgetParameters.

(*---*) import RealOrder.

(* Lower execution-facing FS-programming boundary below `LEFsProgramming.ec`.
   This file introduces the concrete lower names needed to eventually discharge
   the FS-side sdist theorem without collapsing FS programming to the identity. *)

type le_fs_query_row = LEFsProgrammingCoreDefs.le_fs_query_row.

type le_fs_visible_shell = LEFsProgrammingCoreDefs.le_fs_visible_shell.

type le_fs_hidden_programming_state = LEFsProgrammingCoreDefs.le_fs_hidden_programming_state.

type le_fs_programmed_response_carrier = LEFsProgrammingCoreDefs.le_fs_programmed_response_carrier.

op le_fs_query_row_of_observable :
  le_transcript_observable -> le_fs_query_row =
  fun (obs : le_transcript_observable) => {|
    LEFsProgrammingCoreDefs.lefsqr_challenge_seed = le_challenge_seed_obs obs;
    LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest =
      le_programmed_query_digest_obs obs;
  |}.

op le_fs_visible_shell_of_observable :
  le_transcript_observable -> le_fs_visible_shell =
  fun (obs : le_transcript_observable) => {|
    LEFsProgrammingCoreDefs.lefsvs_commitment_coeffs = le_commitment_coeffs obs;
    LEFsProgrammingCoreDefs.lefsvs_t_coeffs = le_t_coeffs obs;
    LEFsProgrammingCoreDefs.lefsvs_z_coeffs = le_z_coeffs obs;
    LEFsProgrammingCoreDefs.lefsvs_challenge_seed_obs =
      le_challenge_seed_obs obs;
    LEFsProgrammingCoreDefs.lefsvs_programmed_query_digest_obs =
      le_programmed_query_digest_obs obs;
    LEFsProgrammingCoreDefs.lefsvs_qssm_event_payload =
      le_qssm_event_payload obs;
  |}.

op le_fs_hidden_programming_state_of_observable :
  le_transcript_observable -> le_fs_hidden_programming_state =
  fun (obs : le_transcript_observable) => {|
    LEFsProgrammingCoreDefs.lefsps_visible_shell =
      le_fs_visible_shell_of_observable obs;
    LEFsProgrammingCoreDefs.lefsps_query_material = le_fs_query_material_obs obs;
  |}.

op le_fs_visible_shell_of_hidden_programming_state :
  le_fs_hidden_programming_state -> le_fs_visible_shell =
  fun (st : le_fs_hidden_programming_state) =>
    LEFsProgrammingCoreDefs.lefsps_visible_shell st.

op le_fs_query_material_of_hidden_programming_state :
  le_fs_hidden_programming_state -> le_query_material =
  fun (st : le_fs_hidden_programming_state) =>
    LEFsProgrammingCoreDefs.lefsps_query_material st.

op le_fs_observable_of_hidden_programming_state :
  le_fs_hidden_programming_state -> le_transcript_observable =
  fun (st : le_fs_hidden_programming_state) =>
    {|
      leto_commitment_coeffs =
        LEFsProgrammingCoreDefs.lefsvs_commitment_coeffs
          (le_fs_visible_shell_of_hidden_programming_state st);
      leto_t_coeffs =
        LEFsProgrammingCoreDefs.lefsvs_t_coeffs
          (le_fs_visible_shell_of_hidden_programming_state st);
      leto_z_coeffs =
        LEFsProgrammingCoreDefs.lefsvs_z_coeffs
          (le_fs_visible_shell_of_hidden_programming_state st);
      leto_challenge_seed_obs =
        LEFsProgrammingCoreDefs.lefsvs_challenge_seed_obs
          (le_fs_visible_shell_of_hidden_programming_state st);
      leto_programmed_query_digest_obs =
        LEFsProgrammingCoreDefs.lefsvs_programmed_query_digest_obs
          (le_fs_visible_shell_of_hidden_programming_state st);
      leto_query_material = le_fs_query_material_of_hidden_programming_state st;
      leto_qssm_event_payload =
        LEFsProgrammingCoreDefs.lefsvs_qssm_event_payload
          (le_fs_visible_shell_of_hidden_programming_state st);
    |}.

op le_fs_hidden_programming_state_update :
  le_fs_hidden_programming_state -> le_fs_hidden_programming_state =
  fun (st : le_fs_hidden_programming_state) => {|
    LEFsProgrammingCoreDefs.lefsps_visible_shell =
      le_fs_visible_shell_of_hidden_programming_state st;
    LEFsProgrammingCoreDefs.lefsps_query_material =
      le_fs_program_query_material
        (le_fs_query_material_of_hidden_programming_state st);
  |}.

op le_fs_programmed_hidden_state_of_observable :
  le_transcript_observable -> le_fs_hidden_programming_state =
  fun (obs : le_transcript_observable) =>
    le_fs_hidden_programming_state_update
      (le_fs_hidden_programming_state_of_observable obs).

op le_fs_surrogate_transform :
  le_transcript_observable -> le_transcript_observable =
  fun (obs : le_transcript_observable) =>
    le_fs_view_surrogate obs.

op le_fs_programmed_response_of_observable :
  le_transcript_observable -> le_fs_programmed_response_carrier =
  fun (obs : le_transcript_observable) => {|
    LEFsProgrammingCoreDefs.lefspc_query_row =
      le_fs_query_row_of_observable obs;
    LEFsProgrammingCoreDefs.lefspc_programmed_view =
      le_fs_surrogate_transform obs;
  |}.

op d_le_pre_fs_programming_view :
  qssm_public_input -> seed -> le_transcript_observable distr =
  fun (x : qssm_public_input) (s : seed) => d_le_post_rejection_view x s.

op d_le_pre_fs_semantic_programming_view :
  qssm_public_input -> seed -> le_transcript_observable distr =
  fun (x : qssm_public_input) (s : seed) =>
    LERejectionSampler.d_le_semantic_post_rejection_view x s.

op d_le_post_fs_programmed_view :
  qssm_public_input -> seed -> le_transcript_observable distr =
  fun (x : qssm_public_input) (s : seed) =>
    dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.

op d_le_post_fs_semantic_programmed_view :
  qssm_public_input -> seed -> le_transcript_observable distr =
  fun (x : qssm_public_input) (s : seed) =>
    dmap (d_le_pre_fs_semantic_programming_view x s) le_fs_surrogate_transform.

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

type le_fs_shadow_hidden_material = LEFsProgrammingShadowBranch.le_fs_shadow_hidden_material.

type le_fs_shadow_state = LEFsProgrammingShadowBranch.le_fs_shadow_state.

(* The FS layer consumes the primitive category law through its derived
   boolean bad-branch view so the theorem-facing branch/programming bridge can
   stay stable while the primitive category masses evolve. *)
op d_le_fs_shadow_branch_choice : bool distr =
  BudgetParameters.d_le_fs_semantic_branch_choice.

op le_fs_shadow_local_bad_branch_mass : real =
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad).

lemma le_fs_shadow_branch_choice_lossless :
  is_lossless d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_lossless.
qed.

lemma le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic :
  le_fs_shadow_local_bad_branch_mass <= BudgetParameters.epsilon_le_fs_semantic.
proof.
have H := LEFsProgrammingFailureProbability.le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic.
rewrite /le_fs_shadow_local_bad_branch_mass.
rewrite /LEFsProgrammingFailureProbability.le_fs_shadow_local_bad_branch_mass in H.
exact H.
qed.

op le_fs_shadow_hidden_material_of_observable_branch
  (obs : le_transcript_observable) (bad : bool) : le_fs_shadow_hidden_material =
  {| LEFsProgrammingShadowBranch.lefshm_query_row =
       le_fs_query_row_of_observable obs;
     LEFsProgrammingShadowBranch.lefshm_pre_query_material =
       le_fs_shadow_pre_query_material_of_observable obs bad;
     LEFsProgrammingShadowBranch.lefshm_semantic_post_query_material =
       le_fs_shadow_semantic_post_query_material_of_observable obs;
     LEFsProgrammingShadowBranch.lefshm_programmed_response =
       le_fs_programmed_response_of_observable obs;
     LEFsProgrammingShadowBranch.lefshm_bad_flag = bad |}.

op le_fs_shadow_semantic_post_observable
  (hm : le_fs_shadow_hidden_material) : le_transcript_observable =
  {| leto_commitment_coeffs =
       le_commitment_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_t_coeffs =
       le_t_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_z_coeffs =
       le_z_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_challenge_seed_obs =
       le_challenge_seed_obs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_programmed_query_digest_obs =
       le_programmed_query_digest_obs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_query_material = hm.`lefshm_semantic_post_query_material;
     leto_qssm_event_payload =
       le_qssm_event_payload
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
  |}.

op le_fs_shadow_semantic_programmed_view_of_observable
  (obs : le_transcript_observable) : le_transcript_observable =
  le_fs_shadow_semantic_post_observable
    (le_fs_shadow_hidden_material_of_observable_branch obs true).

op le_fs_shadow_semantic_branch_image_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_transcript_observable =
  if bad
  then le_fs_shadow_semantic_programmed_view_of_observable obs
  else le_fs_surrogate_transform obs.

op d_le_fs_shadow_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_coupled_state x s.

op d_le_fs_shadow_semantic_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_coupled_state x s.

op d_le_fs_shadow_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_pre_marginal x s.

op d_le_fs_shadow_semantic_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_pre_marginal x s.

op d_le_fs_shadow_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_post_marginal x s.

op d_le_fs_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_post_marginal x s.

op d_le_fs_shadow_semantic_good_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_good_branch_image x s.

op d_le_fs_shadow_semantic_bad_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_bad_branch_image x s.

lemma d_le_pre_fs_programming_view_dunit
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
proof.
exact (LEFsProgrammingMarginalHelpers.d_le_pre_fs_programming_view_dunit x s).
qed.

lemma d_le_fs_shadow_pre_marginal_matches_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_post_rejection_view x s.
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_pre_marginal_matches_post_rejection_view.
qed.

lemma d_le_fs_shadow_post_marginal_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_post_marginal x s = d_le_post_fs_programmed_view x s.
proof.
exact LEFsProgrammingPostMarginal.d_le_fs_shadow_post_marginal_matches_programmed_view.
qed.

lemma le_fs_surrogate_transform_id
  (obs : le_transcript_observable) :
  le_fs_surrogate_transform obs = obs.
proof.
exact (LEFsProgrammingPostMarginal.le_fs_surrogate_transform_id obs).
qed.

lemma d_le_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_semantic_programmed_view x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit false)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingPostMarginal.d_le_post_fs_semantic_programmed_view_pairE.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingPostMarginal.d_le_fs_shadow_semantic_post_marginal_branch_split_pairE.
qed.

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_semantic_programmed_view x s)
      <= le_fs_shadow_local_bad_branch_mass.
proof.
exact LEFsProgrammingPostMarginal.A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass.
qed.

lemma A_LE_fs_shadow_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_pre_marginal x s)
      (d_le_fs_shadow_post_marginal x s)
      <= le_fs_shadow_failure_probability x s.
proof.
exact LEFsProgrammingFailureProbability.A_LE_fs_shadow_sdist_le_failure_probability.
qed.

lemma A_LE_fs_shadow_failure_probability_le_budget :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_failure_probability x s <= BudgetParameters.epsilon_le_fs.
proof.
exact LEFsProgrammingFailureProbability.A_LE_fs_shadow_failure_probability_le_budget.
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