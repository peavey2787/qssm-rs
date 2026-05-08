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
require import LEFsProgrammingMarginals.
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

op le_fs_shadow_branch_support : bool list =
  BudgetParameters.le_fs_semantic_branch_support.

(* The FS layer consumes the primitive category law through its derived
   boolean bad-branch view so the theorem-facing branch/programming bridge can
   stay stable while the primitive category masses evolve. *)
op d_le_fs_shadow_branch_choice : bool distr =
  BudgetParameters.d_le_fs_semantic_branch_choice.

op d_le_fs_shadow_category_choice :
  BudgetParameters.le_fs_semantic_branch_category distr =
  BudgetParameters.d_le_fs_semantic_branch_category_choice.

lemma d_le_fs_shadow_branch_choice_category_projectionE :
  d_le_fs_shadow_branch_choice =
  dmap d_le_fs_shadow_category_choice
    BudgetParameters.le_fs_semantic_branch_category_is_failure.
proof.
rewrite /d_le_fs_shadow_branch_choice /d_le_fs_shadow_category_choice.
by rewrite /BudgetParameters.d_le_fs_semantic_branch_choice.
qed.

op le_fs_shadow_local_bad_branch_mass : real =
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad).

lemma le_fs_shadow_branch_support_uniq :
  uniq le_fs_shadow_branch_support.
proof.
rewrite /le_fs_shadow_branch_support.
exact BudgetParameters.le_fs_semantic_branch_support_uniq.
qed.

lemma le_fs_shadow_branch_choice_lossless :
  is_lossless d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_lossless.
qed.

lemma le_fs_shadow_good_branch_has_support :
  false \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_good_branch_has_support.
qed.

lemma le_fs_shadow_bad_branch_has_support :
  true \in d_le_fs_shadow_branch_choice.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_bad_branch_has_support.
qed.

lemma le_fs_shadow_branch_choice_mass_false :
  mu1 d_le_fs_shadow_branch_choice false =
  (BudgetParameters.total_slot_count - BudgetParameters.bad_slot_count)%r /
  BudgetParameters.total_slot_count%r.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_mass_false.
qed.

lemma le_fs_shadow_branch_choice_mass_true :
  mu1 d_le_fs_shadow_branch_choice true =
  BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof.
rewrite /d_le_fs_shadow_branch_choice.
exact BudgetParameters.le_fs_semantic_branch_choice_mass_true.
qed.

lemma le_fs_shadow_local_bad_branch_mass_is_true_mass :
  le_fs_shadow_local_bad_branch_mass = mu1 d_le_fs_shadow_branch_choice true.
proof.
rewrite /le_fs_shadow_local_bad_branch_mass.
have Hmu1 : mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad) =
    mu1 d_le_fs_shadow_branch_choice true.
  apply/mu_eq=> bad /=.
  by case: bad.
exact Hmu1.
qed.

lemma le_fs_shadow_local_bad_branch_mass_closed_form :
  le_fs_shadow_local_bad_branch_mass =
  BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof.
rewrite le_fs_shadow_local_bad_branch_mass_is_true_mass.
exact le_fs_shadow_branch_choice_mass_true.
qed.

lemma le_fs_shadow_local_bad_branch_mass_eq_epsilon_le_fs_semantic :
  le_fs_shadow_local_bad_branch_mass = BudgetParameters.epsilon_le_fs_semantic.
proof.
rewrite le_fs_shadow_local_bad_branch_mass_is_true_mass.
rewrite /d_le_fs_shadow_branch_choice /BudgetParameters.epsilon_le_fs_semantic.
by [].
qed.

lemma le_fs_shadow_local_bad_branch_mass_le_epsilon_le_fs_semantic :
  le_fs_shadow_local_bad_branch_mass <= BudgetParameters.epsilon_le_fs_semantic.
proof.
rewrite le_fs_shadow_local_bad_branch_mass_eq_epsilon_le_fs_semantic.
by [].
qed.

lemma le_fs_shadow_local_bad_branch_mass_nonneg :
  0%r <= le_fs_shadow_local_bad_branch_mass.
proof.
rewrite /le_fs_shadow_local_bad_branch_mass.
have Hsub :
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => ! bad) <=
  mu d_le_fs_shadow_branch_choice predT.
  apply mu_sub => bad /=.
  by case: bad.
have Hnot :
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => ! bad) =
  mu d_le_fs_shadow_branch_choice predT -
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad).
  by rewrite mu_not /weight.
move: Hsub.
rewrite Hnot.
by smt().
qed.

op le_fs_shadow_programming_log_of_observable
  (obs : le_transcript_observable) : digest list =
  [le_challenge_seed_obs obs; le_programmed_query_digest_obs obs].

op le_fs_shadow_pre_query_material_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_query_material =
  {| leqm_row_challenge_seed =
       (le_fs_query_material_obs obs).`leqm_row_challenge_seed;
     leqm_row_programmed_query_digest =
       (le_fs_query_material_obs obs).`leqm_row_programmed_query_digest;
     leqm_programmed_response_digest =
       (le_fs_query_material_obs obs).`leqm_programmed_response_digest;
     leqm_programming_log =
       (le_fs_query_material_obs obs).`leqm_programming_log;
     leqm_bad_flag = bad |}.

op le_fs_shadow_semantic_post_query_material_of_observable
  (obs : le_transcript_observable) : le_query_material =
  {| leqm_row_challenge_seed = le_challenge_seed_obs obs;
     leqm_row_programmed_query_digest = le_programmed_query_digest_obs obs;
     leqm_programmed_response_digest = le_programmed_query_digest_obs obs;
     leqm_programming_log = le_fs_shadow_programming_log_of_observable obs;
     leqm_bad_flag = false |}.

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

op le_fs_shadow_hidden_material_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_hidden_material =
  le_fs_shadow_hidden_material_of_observable_branch obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

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

op le_fs_shadow_post_of_observable
  (obs : le_transcript_observable) (hm : le_fs_shadow_hidden_material) :
  le_transcript_observable =
  if hm.`lefshm_bad_flag
  then le_fs_shadow_semantic_post_observable hm
  else le_fs_surrogate_transform obs.

op le_fs_shadow_projected_post_of_hidden_material
  (hm : le_fs_shadow_hidden_material) : le_transcript_observable =
  LEFsProgrammingCoreDefs.lefspc_programmed_view hm.`lefshm_programmed_response.

op le_fs_shadow_projected_post_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_transcript_observable =
  le_fs_shadow_projected_post_of_hidden_material
    (le_fs_shadow_hidden_material_of_observable_branch obs bad).

op le_fs_shadow_state_of_branch_observable
  (obs : le_transcript_observable) (bad : bool) : le_fs_shadow_state =
  let hm = le_fs_shadow_hidden_material_of_observable_branch obs bad in
  {| LEFsProgrammingShadowBranch.lefss_pre_observable = obs;
     LEFsProgrammingShadowBranch.lefss_post_observable =
       le_fs_shadow_projected_post_of_hidden_material hm;
     LEFsProgrammingShadowBranch.lefss_semantic_post_observable =
       le_fs_shadow_post_of_observable obs hm;
     LEFsProgrammingShadowBranch.lefss_hidden_material = hm |}.

op le_fs_shadow_state_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_state =
  le_fs_shadow_state_of_branch_observable obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

op le_fs_shadow_state_of_category_observable
  (obs : le_transcript_observable)
  (category : BudgetParameters.le_fs_semantic_branch_category) : le_fs_shadow_state =
  le_fs_shadow_state_of_branch_observable obs
    (BudgetParameters.le_fs_semantic_branch_category_is_failure category).

op le_fs_shadow_pre_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_pre_observable.

op le_fs_shadow_post_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_post_observable.

op le_fs_shadow_semantic_post_state_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_semantic_post_observable.

op le_fs_shadow_bad_event
  (st : le_fs_shadow_state) : bool =
  (le_fs_query_material_obs st.`lefss_pre_observable).`leqm_bad_flag /\
  ! (le_fs_query_material_obs st.`lefss_post_observable).`leqm_bad_flag.

op le_fs_shadow_semantic_bad_event
  (st : le_fs_shadow_state) : bool =
  st.`lefss_hidden_material.`lefshm_pre_query_material.`leqm_bad_flag /\
  ! (le_fs_query_material_obs st.`lefss_semantic_post_observable).`leqm_bad_flag.

op le_fs_shadow_branch_condition
  (st : le_fs_shadow_state) : bool =
  st.`lefss_hidden_material.`lefshm_bad_flag =
  le_fs_shadow_semantic_bad_event st.

op le_fs_shadow_clean_condition
  (st : le_fs_shadow_state) : bool =
  ! le_fs_shadow_semantic_bad_event st /\
  st.`lefss_semantic_post_observable =
    le_fs_surrogate_transform st.`lefss_pre_observable.

op le_fs_shadow_query_collision_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  LEFsProgrammingCoreDefs.lefsqr_challenge_seed
      st.`lefss_hidden_material.`lefshm_query_row =
    st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_row_challenge_seed /\
  LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
      st.`lefss_hidden_material.`lefshm_query_row =
    st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_row_programmed_query_digest.

op le_fs_shadow_programming_collision_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_programmed_response_digest =
    LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
      st.`lefss_hidden_material.`lefshm_query_row /\
  st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_programming_log =
    [ LEFsProgrammingCoreDefs.lefsqr_challenge_seed
        st.`lefss_hidden_material.`lefshm_query_row;
      LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
        st.`lefss_hidden_material.`lefshm_query_row ].

op le_fs_shadow_transcript_mismatch_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  le_challenge_seed_obs st.`lefss_semantic_post_observable =
    le_challenge_seed_obs st.`lefss_post_observable /\
  le_programmed_query_digest_obs st.`lefss_semantic_post_observable =
    le_programmed_query_digest_obs st.`lefss_post_observable /\
  ! (le_fs_query_material_obs st.`lefss_semantic_post_observable).`leqm_bad_flag.

op le_fs_shadow_semantic_category_condition
  (category : BudgetParameters.le_fs_semantic_branch_category)
  (st : le_fs_shadow_state) : bool =
  if pred1 BudgetParameters.LEFSSemanticBranchClean category then
    le_fs_shadow_clean_condition st
  else if pred1 BudgetParameters.LEFSSemanticBranchQueryCollision category then
    le_fs_shadow_query_collision_condition st
  else if pred1 BudgetParameters.LEFSSemanticBranchProgrammingCollision category then
    le_fs_shadow_programming_collision_condition st
  else le_fs_shadow_transcript_mismatch_condition st.

pred le_fs_shadow_good_event
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) =
  ! (le_fs_query_material_obs obs).`leqm_bad_flag.

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

op le_fs_shadow_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_bad_event)
    (fun (bad : bool) => bad).

op le_fs_shadow_semantic_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_fs_shadow_semantic_coupled_state x s) le_fs_shadow_semantic_bad_event)
    (fun (bad : bool) => bad).

lemma le_fs_shadow_hidden_bad_flag_matches_pre_query_material
  (obs : le_transcript_observable) :
  (le_fs_shadow_hidden_material_of_observable obs).`lefshm_bad_flag =
  (le_fs_query_material_obs obs).`leqm_bad_flag.
proof.
by rewrite /le_fs_shadow_hidden_material_of_observable
  /le_fs_shadow_hidden_material_of_observable_branch.
qed.

lemma le_fs_shadow_semantic_post_observable_bad_flag_false
  (obs : le_transcript_observable) :
  ! (le_fs_query_material_obs
      ((le_fs_shadow_state_of_observable obs).`lefss_semantic_post_observable)).`leqm_bad_flag.
proof.
rewrite /le_fs_shadow_state_of_observable /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_post_of_observable /=.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_query_material_obs /=.
case: (obs.`leto_query_material.`leqm_bad_flag) => /=.
- rewrite /le_fs_shadow_semantic_post_observable /=.
  by rewrite /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by rewrite /le_fs_program_query_material.
qed.

lemma le_fs_shadow_dmap_dprod_fst_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
exact (LEFsProgrammingMarginals.le_fs_shadow_dmap_dprod_fst_lossless da db Hll).
qed.

lemma d_le_pre_fs_programming_view_dunit
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
proof.
exact (LEFsProgrammingMarginals.d_le_pre_fs_programming_view_dunit x s).
qed.

lemma d_le_pre_fs_semantic_programming_view_fixed_branch_imageE
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_semantic_programming_view x s =
    dmap LERejectionSampler.d_le_rejection_shadow_semantic_branch_choice
      (fun reject =>
        LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable
          x s (le_real_execution_observable x s) reject).
proof.
exact (LEFsProgrammingMarginals.d_le_pre_fs_semantic_programming_view_fixed_branch_imageE x s).
qed.

lemma d_le_pre_fs_semantic_programming_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_pre_fs_semantic_programming_view x s).
proof.
exact (LEFsProgrammingMarginals.d_le_pre_fs_semantic_programming_view_lossless x s).
qed.

lemma d_le_fs_shadow_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_coupled_state x s =
      dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_coupled_state_pairE.
qed.

lemma d_le_fs_shadow_semantic_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_coupled_state x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_coupled_state_pairE.
qed.

lemma le_fs_shadow_semantic_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_semantic_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = bad.
proof.
exact (LEFsProgrammingMarginals.le_fs_shadow_semantic_bad_event_branch_stateE obs bad).
qed.

lemma le_fs_shadow_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = false.
proof.
exact (LEFsProgrammingMarginals.le_fs_shadow_bad_event_branch_stateE obs bad).
qed.

lemma le_fs_shadow_semantic_post_of_observable_good_branch_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  (le_fs_shadow_state_of_branch_observable obs false).`lefss_semantic_post_observable =
  le_fs_surrogate_transform obs.
proof.
exact (LEFsProgrammingMarginals.le_fs_shadow_semantic_post_of_observable_good_branch_supportE x s obs).
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
exact LEFsProgrammingMarginals.d_le_fs_shadow_post_marginal_matches_programmed_view.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_bad_branch_image x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit true)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_bad_branch_image_pairE.
qed.

lemma d_le_fs_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_fs_shadow_post_marginal x s.
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_pre_post_marginals_equal.
qed.

lemma le_fs_surrogate_transform_id
  (obs : le_transcript_observable) :
  le_fs_surrogate_transform obs = obs.
proof.
exact (LEFsProgrammingMarginals.le_fs_surrogate_transform_id obs).
qed.

lemma d_le_fs_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_fs_shadow_state_of_branch_observable (fst p) (snd p)).`lefss_semantic_post_observable).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_post_marginal_pairE.
qed.

lemma d_le_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_semantic_programmed_view x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` dunit false)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_post_fs_semantic_programmed_view_pairE.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
exact LEFsProgrammingMarginals.d_le_fs_shadow_semantic_post_marginal_branch_split_pairE.
qed.

lemma le_fs_shadow_branch_choice_sdist_dunit_false_le_bad_branch_mass :
  sdist d_le_fs_shadow_branch_choice (dunit false) <=
  le_fs_shadow_local_bad_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE : mu d_le_fs_shadow_branch_choice E = mu d_le_fs_shadow_branch_choice predT.
      apply/mu_eq=> bad /=.
      by case: bad=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_fs_shadow_branch_choice = 1%r.
      exact (is_losslessP _ le_fs_shadow_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE : mu d_le_fs_shadow_branch_choice E = mu1 d_le_fs_shadow_branch_choice false.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE le_fs_shadow_branch_choice_mass_false.
  rewrite le_fs_shadow_local_bad_branch_mass_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE : mu d_le_fs_shadow_branch_choice E = mu1 d_le_fs_shadow_branch_choice true.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE le_fs_shadow_branch_choice_mass_true.
  rewrite le_fs_shadow_local_bad_branch_mass_closed_form.
  by smt().
have HE : mu d_le_fs_shadow_branch_choice E = mu d_le_fs_shadow_branch_choice pred0.
  apply/mu_eq=> bad /=.
  by case: bad=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_fs_shadow_local_bad_branch_mass_closed_form.
by smt().
qed.

lemma le_fs_shadow_branch_choice_sdist_dunit_falseE :
  sdist d_le_fs_shadow_branch_choice (dunit false) =
  le_fs_shadow_local_bad_branch_mass.
proof.
apply ler_anti.
have Hlb :
    `|mu d_le_fs_shadow_branch_choice (pred1 true) -
      mu (dunit false) (pred1 true)| <=
    sdist d_le_fs_shadow_branch_choice (dunit false).
  exact (sdist_upper_bound d_le_fs_shadow_branch_choice (dunit false) (pred1 true)).
move: Hlb.
rewrite (dunitE (pred1 true) false) /=.
move=> Hlb.
have Habs : le_fs_shadow_local_bad_branch_mass =
    `|mu d_le_fs_shadow_branch_choice (pred1 true) - 0%r|.
  have Hnonneg : 0%r <= mu d_le_fs_shadow_branch_choice (pred1 true).
    exact (ge0_mu1 d_le_fs_shadow_branch_choice true).
  have Hmass : le_fs_shadow_local_bad_branch_mass =
      mu d_le_fs_shadow_branch_choice (pred1 true).
    exact le_fs_shadow_local_bad_branch_mass_is_true_mass.
  smt().
by smt().
qed.

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_branch_choice_distance :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_semantic_programmed_view x s)
      <= sdist d_le_fs_shadow_branch_choice (dunit false).
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite (d_le_post_fs_semantic_programmed_view_pairE x s).
pose dpre := d_le_pre_fs_semantic_programming_view x s.
pose F := fun (p : le_transcript_observable * bool) =>
  le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p).
have Hmap :
  sdist (dmap (dpre `*` d_le_fs_shadow_branch_choice) F)
        (dmap (dpre `*` dunit false) F)
    <= sdist (dpre `*` d_le_fs_shadow_branch_choice)
         (dpre `*` dunit false).
  exact (sdist_dmap (dpre `*` d_le_fs_shadow_branch_choice)
    (dpre `*` dunit false) F).
have Hdprod :
  sdist (dpre `*` d_le_fs_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist dpre dpre + sdist d_le_fs_shadow_branch_choice (dunit false).
  exact (sdist_dprod dpre dpre d_le_fs_shadow_branch_choice (dunit false)).
have Hdprod' :
  sdist (dpre `*` d_le_fs_shadow_branch_choice)
        (dpre `*` dunit false)
    <= sdist d_le_fs_shadow_branch_choice (dunit false).
  have Hsame : sdist dpre dpre <= 0%r.
    by rewrite sdistdd.
  have Hsum :
    sdist dpre dpre + sdist d_le_fs_shadow_branch_choice (dunit false) <=
    0%r + sdist d_le_fs_shadow_branch_choice (dunit false).
    apply (ler_add _ _ _ _ Hsame).
    by [].
  have Hstep :
    sdist (dpre `*` d_le_fs_shadow_branch_choice)
          (dpre `*` dunit false) <=
    0%r + sdist d_le_fs_shadow_branch_choice (dunit false).
    exact (ler_trans _ _ _ Hdprod Hsum).
  by smt().
apply (ler_trans _ _ _ Hmap).
exact (ler_trans _ _ _ Hdprod').
qed.

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_semantic_programmed_view x s)
      <= le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s.
have Hdist := A_LE_fs_shadow_semantic_post_marginal_sdist_le_branch_choice_distance x s.
rewrite le_fs_shadow_branch_choice_sdist_dunit_falseE in Hdist.
exact Hdist.
qed.

lemma le_real_execution_observable_in_pre_fs_programming_view
  (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_pre_fs_programming_view x s.
proof.
rewrite (d_le_pre_fs_programming_view_dunit x s).
by rewrite supp_dunit.
qed.

lemma le_real_execution_observable_in_pre_fs_semantic_programming_view
  (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_pre_fs_semantic_programming_view x s.
proof.
rewrite (d_le_pre_fs_semantic_programming_view_fixed_branch_imageE x s).
rewrite supp_dmap.
exists false; split.
  exact LERejectionSampler.le_rejection_shadow_semantic_accept_branch_has_support.
rewrite /LERejectionSampler.le_rejection_shadow_semantic_branch_image_of_observable.
have Hacc :
    le_real_execution_observable x s =
    LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch
      x s (le_real_execution_observable x s) false.
  by rewrite eq_sym
    (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id
      x s (le_real_execution_observable x s)).
exact Hacc.
qed.

lemma le_fs_shadow_semantic_post_marginal_support
  (x : qssm_public_input) (s : seed)
  (obs : le_transcript_observable) (bad : bool) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  bad \in d_le_fs_shadow_branch_choice =>
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hobs Hbad.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s).
rewrite supp_dmap.
exists (obs, bad); split.
  by rewrite supp_dprod Hobs Hbad.
by [].
qed.

lemma le_fs_shadow_semantic_post_good_branch_support
  (x : qssm_public_input) (s : seed) :
  (le_fs_shadow_state_of_branch_observable
     (le_real_execution_observable x s) false).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
apply (le_fs_shadow_semantic_post_marginal_support x s
  (le_real_execution_observable x s) false).
  exact (le_real_execution_observable_in_pre_fs_semantic_programming_view x s).
exact le_fs_shadow_good_branch_has_support.
qed.

lemma le_fs_shadow_semantic_post_bad_branch_support
  (x : qssm_public_input) (s : seed) :
  (le_fs_shadow_state_of_branch_observable
     (le_real_execution_observable x s) true).`lefss_semantic_post_observable
    \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
apply (le_fs_shadow_semantic_post_marginal_support x s
  (le_real_execution_observable x s) true).
  exact (le_real_execution_observable_in_pre_fs_semantic_programming_view x s).
exact le_fs_shadow_bad_branch_has_support.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_semantic_post_marginal x s =>
  exists (pre_obs : le_transcript_observable) (bad : bool),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    bad \in d_le_fs_shadow_branch_choice /\
    obs =
      (le_fs_shadow_state_of_branch_observable pre_obs bad).`lefss_semantic_post_observable.
proof.
move=> Hobs.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s) in Hobs.
case/supp_dmap: Hobs=> -[pre_obs bad] [Hp ->].
move: Hp; rewrite supp_dprod => -[Hpre Hbad].
exists pre_obs.
exists bad.
by [].
qed.

lemma le_fs_shadow_semantic_good_branch_image_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_surrogate_transform obs
    \in d_le_fs_shadow_semantic_good_branch_image x s.
proof.
move=> Hobs.
rewrite /d_le_fs_shadow_semantic_good_branch_image.
rewrite /LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_good_branch_image.
rewrite /d_le_post_fs_semantic_programmed_view.
rewrite supp_dmap.
exists obs; split.
  exact Hobs.
by [].
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_supportE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_good_branch_image x s =>
  exists (pre_obs : le_transcript_observable),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs = le_fs_surrogate_transform pre_obs.
proof.
move=> Hpost.
rewrite /d_le_fs_shadow_semantic_good_branch_image in Hpost.
rewrite /LEFsProgrammingCoupledState.d_le_fs_shadow_semantic_good_branch_image in Hpost.
rewrite /d_le_post_fs_semantic_programmed_view in Hpost.
case/supp_dmap: Hpost=> pre_obs [Hpre ->].
exists pre_obs; split.
  exact Hpre.
by [].
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_support_sub_postE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_good_branch_image x s =>
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hpost.
have [pre_obs [Hpre Himage]] :=
  d_le_fs_shadow_semantic_good_branch_image_supportE x s post_obs Hpost.
have Hgood :
    (le_fs_shadow_state_of_branch_observable pre_obs false).`lefss_semantic_post_observable
      \in d_le_fs_shadow_semantic_post_marginal x s.
  exact (le_fs_shadow_semantic_post_marginal_support x s pre_obs false Hpre
    le_fs_shadow_good_branch_has_support).
rewrite (le_fs_shadow_semantic_post_of_observable_good_branch_supportE x s pre_obs Hpre) in Hgood.
rewrite Himage.
exact Hgood.
qed.

lemma le_fs_shadow_semantic_bad_branch_image_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_semantic_programming_view x s =>
  le_fs_shadow_semantic_programmed_view_of_observable obs
    \in d_le_fs_shadow_semantic_bad_branch_image x s.
proof.
move=> Hobs.
rewrite (d_le_fs_shadow_semantic_bad_branch_image_pairE x s).
rewrite supp_dmap.
exists (obs, true); split.
  by rewrite supp_dprod Hobs supp_dunit.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_supportE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_bad_branch_image x s =>
  exists (pre_obs : le_transcript_observable),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs = le_fs_shadow_semantic_programmed_view_of_observable pre_obs.
proof.
move=> Hpost.
rewrite (d_le_fs_shadow_semantic_bad_branch_image_pairE x s) in Hpost.
case/supp_dmap: Hpost=> -[pre_obs bad] [Hp ->].
move: Hp; rewrite supp_dprod supp_dunit => -[Hpre ->].
exists pre_obs; split.
  exact Hpre.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
qed.

lemma d_le_fs_shadow_semantic_bad_branch_image_support_sub_postE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_bad_branch_image x s =>
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s.
proof.
move=> Hpost.
have [pre_obs [Hpre Himage]] :=
  d_le_fs_shadow_semantic_bad_branch_image_supportE x s post_obs Hpost.
have Hbad :
    (le_fs_shadow_state_of_branch_observable pre_obs true).`lefss_semantic_post_observable
      \in d_le_fs_shadow_semantic_post_marginal x s.
  exact (le_fs_shadow_semantic_post_marginal_support x s pre_obs true Hpre
    le_fs_shadow_bad_branch_has_support).
rewrite (le_fs_shadow_semantic_post_bad_branch_matches_semantic_programmed_view pre_obs) in Hbad.
rewrite Himage.
exact Hbad.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_support_tagged_imageE
  (x : qssm_public_input) (s : seed) (post_obs : le_transcript_observable) :
  post_obs \in d_le_fs_shadow_semantic_post_marginal x s =>
  exists (pre_obs : le_transcript_observable) (b : bool),
    pre_obs \in d_le_pre_fs_semantic_programming_view x s /\
    post_obs =
      le_fs_shadow_semantic_branch_image_of_observable pre_obs b.
proof.
move=> Hpost.
rewrite (d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s) in Hpost.
case/supp_dmap: Hpost=> -[pre_obs b] [Hp ->].
move: Hp; rewrite supp_dprod => -[Hpre _].
exists pre_obs; exists b; split.
  exact Hpre.
by [].
qed.

lemma d_le_fs_shadow_bad_event_image_zero :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_bad_event = dunit false.
proof.
move=> x s.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_bad_event
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_bad_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) => false).
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /(\o) (le_fs_shadow_bad_event_branch_stateE obs bad).
rewrite Hmap.
rewrite -(dmap_comp fst (fun (_ : le_transcript_observable) => false)
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
rewrite (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_shadow_branch_choice_lossless).
rewrite (d_le_pre_fs_programming_view_dunit x s).
by rewrite dmap_dunit.
qed.

lemma le_fs_shadow_failure_probability_zero :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_failure_probability x s = 0%r.
proof.
move=> x s.
rewrite /le_fs_shadow_failure_probability.
rewrite (d_le_fs_shadow_bad_event_image_zero x s).
by rewrite dunitE /=.
qed.

lemma d_le_fs_shadow_semantic_bad_event_image_branch_choice :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_fs_shadow_semantic_coupled_state x s) le_fs_shadow_semantic_bad_event =
      d_le_fs_shadow_branch_choice.
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_semantic_bad_event
  ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_semantic_bad_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_semantic_programming_view x s) `*` d_le_fs_shadow_branch_choice) snd.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /(\o) (le_fs_shadow_semantic_bad_event_branch_stateE obs bad).
rewrite Hmap.
exact (le_fs_shadow_dmap_dprod_snd_lossless
  (d_le_pre_fs_semantic_programming_view x s) d_le_fs_shadow_branch_choice
  (d_le_pre_fs_semantic_programming_view_lossless x s)).
qed.

lemma le_fs_shadow_semantic_failure_probability_exact_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_semantic_failure_probability x s =
    le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s.
rewrite /le_fs_shadow_semantic_failure_probability /le_fs_shadow_local_bad_branch_mass.
rewrite (d_le_fs_shadow_semantic_bad_event_image_branch_choice x s).
by [].
qed.

lemma le_fs_shadow_semantic_failure_probability_closed_form :
  forall (x : qssm_public_input) (s : seed),
    le_fs_shadow_semantic_failure_probability x s =
    BudgetParameters.bad_slot_count%r / BudgetParameters.total_slot_count%r.
proof.
move=> x s.
rewrite le_fs_shadow_semantic_failure_probability_exact_branch_mass.
exact le_fs_shadow_local_bad_branch_mass_closed_form.
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

lemma A_LE_fs_shadow_sdist_le_semantic_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_pre_marginal x s)
      (d_le_fs_shadow_post_marginal x s)
      <= le_fs_shadow_semantic_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_fs_shadow_pre_post_marginals_equal x s).
rewrite sdistdd.
rewrite (le_fs_shadow_semantic_failure_probability_exact_branch_mass x s).
rewrite /le_fs_shadow_local_bad_branch_mass.
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