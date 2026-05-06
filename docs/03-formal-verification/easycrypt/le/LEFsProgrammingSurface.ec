require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
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
  lefss_semantic_post_observable : le_transcript_observable;
  lefss_hidden_material : le_fs_shadow_hidden_material;
}.

op le_fs_shadow_branch_support : bool list =
  BudgetParameters.le_fs_semantic_branch_support.

op d_le_fs_shadow_branch_choice : bool distr =
  BudgetParameters.d_le_fs_semantic_branch_choice.

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
  {| lefshm_query_row = le_fs_query_row_of_observable obs;
     lefshm_pre_query_material =
       le_fs_shadow_pre_query_material_of_observable obs bad;
     lefshm_semantic_post_query_material =
       le_fs_shadow_semantic_post_query_material_of_observable obs;
     lefshm_programmed_response = le_fs_programmed_response_of_observable obs;
     lefshm_bad_flag = bad |}.

op le_fs_shadow_hidden_material_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_hidden_material =
  le_fs_shadow_hidden_material_of_observable_branch obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

op le_fs_shadow_semantic_post_observable
  (hm : le_fs_shadow_hidden_material) : le_transcript_observable =
  {| leto_commitment_coeffs =
       le_commitment_coeffs
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
     leto_t_coeffs =
       le_t_coeffs
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
     leto_z_coeffs =
       le_z_coeffs
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
     leto_challenge_seed_obs =
       le_challenge_seed_obs
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
     leto_programmed_query_digest_obs =
       le_programmed_query_digest_obs
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
     leto_query_material = hm.`lefshm_semantic_post_query_material;
     leto_qssm_event_payload =
       le_qssm_event_payload
         hm.`lefshm_programmed_response.`lefspc_programmed_view;
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
  hm.`lefshm_programmed_response.`lefspc_programmed_view.

op le_fs_shadow_state_of_branch_observable
  (obs : le_transcript_observable) (bad : bool) : le_fs_shadow_state =
  let hm = le_fs_shadow_hidden_material_of_observable_branch obs bad in
  {| lefss_pre_observable = obs;
     lefss_post_observable = le_fs_shadow_projected_post_of_hidden_material hm;
     lefss_semantic_post_observable = le_fs_shadow_post_of_observable obs hm;
     lefss_hidden_material = hm |}.

op le_fs_shadow_state_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_state =
  le_fs_shadow_state_of_branch_observable obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

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

pred le_fs_shadow_good_event
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) =
  ! (le_fs_query_material_obs obs).`leqm_bad_flag.

op d_le_fs_shadow_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_state_of_branch_observable (fst p) (snd p)).

op d_le_fs_shadow_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_pre_observable.

op d_le_fs_shadow_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_post_observable.

op d_le_fs_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    le_fs_shadow_semantic_post_state_observable.

op d_le_fs_shadow_semantic_good_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_programming_view x s) le_fs_surrogate_transform.

op d_le_fs_shadow_semantic_bad_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_pre_fs_programming_view x s)
    le_fs_shadow_semantic_programmed_view_of_observable.

op le_fs_shadow_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_bad_event)
    (fun (bad : bool) => bad).

op le_fs_shadow_semantic_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_semantic_bad_event)
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

lemma le_fs_shadow_semantic_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_semantic_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = bad.
proof.
rewrite /le_fs_shadow_semantic_bad_event /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_post_of_observable /=.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_shadow_pre_query_material_of_observable /=.
case: bad => /=.
- rewrite /le_fs_shadow_semantic_post_observable /=.
  by rewrite /le_fs_query_material_obs /le_fs_shadow_semantic_post_query_material_of_observable.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by rewrite /le_fs_program_query_material.
qed.

lemma le_fs_shadow_bad_event_branch_stateE
  (obs : le_transcript_observable) (bad : bool) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_branch_observable obs bad) = false.
proof.
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
case: qmat=> rowseed rowdig respdig log badflag /=.
rewrite /le_fs_shadow_bad_event /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable /=.
rewrite /le_fs_query_material_obs /=.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate /le_fs_program_query_material /=.
by smt().
qed.

lemma le_fs_shadow_bad_event_stateE
  (obs : le_transcript_observable) :
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
rewrite /le_fs_shadow_state_of_observable.
exact (le_fs_shadow_bad_event_branch_stateE obs
  ((le_fs_query_material_obs obs).`leqm_bad_flag)).
qed.

lemma le_fs_shadow_post_of_observable_matches_surrogate
  (obs : le_transcript_observable) :
  ! (le_fs_query_material_obs obs).`leqm_bad_flag =>
  (le_fs_shadow_state_of_observable obs).`lefss_post_observable =
  le_fs_surrogate_transform obs.
proof.
move=> _.
rewrite /le_fs_shadow_state_of_observable /le_fs_shadow_state_of_branch_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
by [].
qed.

lemma le_fs_shadow_semantic_post_observable_preserves_visible_fields
  (obs : le_transcript_observable) :
  le_commitment_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_commitment_coeffs obs /\
  le_t_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_t_coeffs obs /\
  le_z_coeffs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_z_coeffs obs /\
  le_challenge_seed_obs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_challenge_seed_obs obs /\
  le_programmed_query_digest_obs
    (le_fs_shadow_semantic_post_observable
       (le_fs_shadow_hidden_material_of_observable obs)) =
    le_programmed_query_digest_obs obs.
proof.
rewrite /le_fs_shadow_semantic_post_observable.
  rewrite /le_fs_shadow_hidden_material_of_observable.
  rewrite /le_fs_shadow_hidden_material_of_observable_branch /=.
rewrite /le_fs_programmed_response_of_observable /=.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by [].
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
rewrite /le_fs_shadow_state_of_observable /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
rewrite /le_commitment_coeffs /le_t_coeffs /le_z_coeffs.
rewrite /le_challenge_seed_obs /le_programmed_query_digest_obs.
rewrite /le_fs_surrogate_transform /le_fs_view_surrogate.
by [].
qed.

lemma le_fs_shadow_semantic_post_good_branch_matches_programmed_view
  (obs : le_transcript_observable) :
  (le_fs_shadow_state_of_branch_observable obs false).`lefss_semantic_post_observable =
  le_fs_surrogate_transform obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable /le_fs_shadow_hidden_material_of_observable_branch.
by [].
qed.

lemma le_fs_shadow_semantic_post_bad_branch_matches_semantic_programmed_view
  (obs : le_transcript_observable) :
  (le_fs_shadow_state_of_branch_observable obs true).`lefss_semantic_post_observable =
  le_fs_shadow_semantic_programmed_view_of_observable obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_semantic_programmed_view_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
by [].
qed.

lemma le_fs_shadow_semantic_post_branch_imageE
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable =
  le_fs_shadow_semantic_branch_image_of_observable obs bad.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_semantic_branch_image_of_observable.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_semantic_programmed_view_of_observable.
case: bad => /=.
- by rewrite /le_fs_shadow_hidden_material_of_observable_branch.
by rewrite /le_fs_shadow_hidden_material_of_observable_branch.
qed.

lemma le_fs_shadow_semantic_post_differs_from_programmed_view_only_on_bad_branch
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_semantic_post_observable <>
    (le_fs_shadow_state_of_branch_observable obs bad).`lefss_post_observable =>
  bad.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /=.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
rewrite /le_fs_programmed_response_of_observable.
by case: bad => /=.
qed.

lemma le_fs_shadow_projected_post_branch_matches_surrogate
  (obs : le_transcript_observable) (bad : bool) :
  (le_fs_shadow_state_of_branch_observable obs bad).`lefss_post_observable =
  le_fs_surrogate_transform obs.
proof.
rewrite /le_fs_shadow_state_of_branch_observable /le_fs_shadow_projected_post_of_hidden_material.
rewrite /le_fs_shadow_hidden_material_of_observable_branch /le_fs_programmed_response_of_observable.
by [].
qed.

lemma le_fs_shadow_dmap_dprod_fst_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
rewrite (dprod_marginalL da db (fun (a : 'a) => a)).
rewrite dmap_id.
have Hw : weight db = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma le_fs_shadow_dmap_dprod_snd_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw : weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma d_le_pre_fs_programming_view_dunit
  (x : qssm_public_input) (s : seed) :
  d_le_pre_fs_programming_view x s = dunit (le_real_execution_observable x s).
proof.
rewrite /d_le_pre_fs_programming_view /d_le_post_rejection_view.
rewrite /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit.
by rewrite /le_post_rejection_surrogate.
qed.

lemma d_le_pre_fs_programming_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_pre_fs_programming_view x s).
proof.
rewrite (d_le_pre_fs_programming_view_dunit x s).
rewrite /is_lossless /weight dunitE /=.
by [].
qed.

lemma d_le_fs_shadow_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_coupled_state x s =
      dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_state_of_branch_observable (fst p) (snd p)).
proof.
by move=> x s; rewrite /d_le_fs_shadow_coupled_state.
qed.

lemma le_fs_shadow_semantic_branch_state_has_support
  (x : qssm_public_input) (s : seed)
  (obs : le_transcript_observable) (bad : bool) :
  obs \in d_le_pre_fs_programming_view x s =>
  bad \in d_le_fs_shadow_branch_choice =>
  le_fs_shadow_state_of_branch_observable obs bad \in d_le_fs_shadow_coupled_state x s.
proof.
move=> Hobs Hbad.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite supp_dmap.
exists (obs, bad); split.
  by rewrite supp_dprod Hobs Hbad.
by [].
qed.

lemma le_fs_shadow_semantic_good_branch_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_state_of_branch_observable obs false \in d_le_fs_shadow_coupled_state x s.
proof.
move=> Hobs.
exact (le_fs_shadow_semantic_branch_state_has_support x s obs false Hobs
  le_fs_shadow_good_branch_has_support).
qed.

lemma le_fs_shadow_semantic_bad_branch_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_state_of_branch_observable obs true \in d_le_fs_shadow_coupled_state x s.
proof.
move=> Hobs.
exact (le_fs_shadow_semantic_branch_state_has_support x s obs true Hobs
  le_fs_shadow_bad_branch_has_support).
qed.

lemma le_fs_shadow_bad_event_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_bad_event (le_fs_shadow_state_of_observable obs) = false.
proof.
move=> _.
exact (le_fs_shadow_bad_event_stateE obs).
qed.

lemma le_real_execution_query_material_bad_flag_false
  (x : qssm_public_input) (s : seed) :
  ! (le_real_execution_query_material x s).`leqm_bad_flag.
proof.
rewrite /le_real_execution_query_material /le_real_execution_record_of.
rewrite /le_real_execution_query_material_of_spine /le_real_execution_spine_of.
rewrite /le_real_execution_primitive_material_of /le_real_execution_residual_material_of.
rewrite /le_real_execution_hidden_query_material_of.
by [].
qed.

lemma d_le_pre_fs_programming_view_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  obs = le_real_execution_observable x s.
proof.
move=> Hobs.
rewrite /d_le_pre_fs_programming_view /d_le_post_rejection_view.
rewrite /d_le_real_view /d_le_real_execution_view in Hobs.
case/supp_dmap: Hobs=> pre_obs [Hpre ->].
move: Hpre; rewrite supp_dunit => ->.
by rewrite /le_post_rejection_surrogate.
qed.

lemma le_fs_shadow_good_event_on_pre_programming_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_good_event x s obs.
proof.
move=> Hobs.
rewrite /le_fs_shadow_good_event /le_fs_query_material_obs.
rewrite (d_le_pre_fs_programming_view_supportE x s obs Hobs).
rewrite (le_real_execution_observable_exposes_query_material x s).
exact (le_real_execution_query_material_bad_flag_false x s).
qed.

lemma le_fs_shadow_good_branch_post_matches_surrogate_on_pre_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_pre_fs_programming_view x s =>
  le_fs_shadow_good_event x s obs =>
  le_fs_shadow_post_of_observable obs
    (le_fs_shadow_hidden_material_of_observable obs) =
  le_fs_surrogate_transform obs.
proof.
move=> _ Hgood.
rewrite /le_fs_shadow_post_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable.
rewrite /le_fs_shadow_hidden_material_of_observable_branch.
move: Hgood.
rewrite /le_fs_shadow_good_event /le_fs_query_material_obs.
by case: (obs.`leto_query_material.`leqm_bad_flag).
qed.

lemma d_le_fs_shadow_pre_marginal_matches_pre_programming_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_pre_marginal x s = d_le_pre_fs_programming_view x s.
proof.
move=> x s.
rewrite /d_le_fs_shadow_pre_marginal.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_pre_observable
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /le_fs_shadow_pre_observable /le_fs_shadow_state_of_branch_observable /(\o).
rewrite Hmap.
exact (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_shadow_branch_choice_lossless).
qed.

lemma d_le_fs_shadow_pre_marginal_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_pre_marginal x s =>
  obs = le_real_execution_observable x s.
proof.
move=> Hobs.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view in Hobs.
exact (d_le_pre_fs_programming_view_supportE x s obs Hobs).
qed.

lemma le_fs_shadow_good_event_on_pre_marginal_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_pre_marginal x s =>
  le_fs_shadow_good_event x s obs.
proof.
move=> Hobs.
rewrite d_le_fs_shadow_pre_marginal_matches_pre_programming_view in Hobs.
exact (le_fs_shadow_good_event_on_pre_programming_support x s obs Hobs).
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
rewrite /d_le_fs_shadow_post_marginal.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_post_observable
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_post_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_fs_surrogate_transform (fst p)).
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  rewrite /le_fs_shadow_post_observable /(\o).
  exact (le_fs_shadow_projected_post_branch_matches_surrogate obs bad).
rewrite Hmap.
rewrite -(dmap_comp fst le_fs_surrogate_transform
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
rewrite (le_fs_shadow_dmap_dprod_fst_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  le_fs_shadow_branch_choice_lossless).
by rewrite /d_le_post_fs_programmed_view.
qed.

lemma d_le_fs_shadow_semantic_good_branch_image_matches_programmed_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_good_branch_image x s = d_le_post_fs_programmed_view x s.
proof.
by move=> x s; rewrite /d_le_fs_shadow_semantic_good_branch_image /d_le_post_fs_programmed_view.
qed.

lemma d_le_post_fs_programmed_view_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_fs_programmed_view x s =
      dmap (dunit false)
        (fun bad =>
          le_fs_shadow_semantic_branch_image_of_observable
            (le_real_execution_observable x s) bad).
proof.
move=> x s.
rewrite /d_le_post_fs_programmed_view.
rewrite (d_le_pre_fs_programming_view_dunit x s).
rewrite !dmap_dunit /=.
by rewrite /le_fs_shadow_semantic_branch_image_of_observable.
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

lemma d_le_fs_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_fs_shadow_state_of_branch_observable (fst p) (snd p)).`lefss_semantic_post_observable).
proof.
move=> x s.
rewrite /d_le_fs_shadow_semantic_post_marginal.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_semantic_post_state_observable
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
apply eq_dmap_in=> p _ /=.
case: p=> obs bad /=.
by rewrite /le_fs_shadow_semantic_post_state_observable /(\o).
qed.

lemma d_le_fs_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s).
apply eq_dmap_in=> p _ /=.
case: p=> obs bad /=.
exact (le_fs_shadow_semantic_post_branch_imageE obs bad).
qed.

lemma d_le_fs_shadow_semantic_post_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_shadow_semantic_post_marginal x s =
      dmap d_le_fs_shadow_branch_choice
        (fun bad =>
          le_fs_shadow_semantic_branch_image_of_observable
            (le_real_execution_observable x s) bad).
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite (d_le_pre_fs_programming_view_dunit x s).
have Hmap :
  dmap ((dunit (le_real_execution_observable x s)) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_semantic_branch_image_of_observable (fst p) (snd p)) =
  dmap ((dunit (le_real_execution_observable x s)) `*` d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_fs_shadow_semantic_branch_image_of_observable
        (le_real_execution_observable x s) (snd p)).
  apply eq_dmap_in=> p Hp /=.
  case: p Hp=> obs bad /=.
  rewrite supp_dprod => -[Hobs _].
  move: Hobs; rewrite supp_dunit => ->.
  by [].
rewrite Hmap.
rewrite -(dmap_comp snd
  (fun bad =>
    le_fs_shadow_semantic_branch_image_of_observable
      (le_real_execution_observable x s) bad)
  ((dunit (le_real_execution_observable x s)) `*` d_le_fs_shadow_branch_choice)).
rewrite (le_fs_shadow_dmap_dprod_snd_lossless
  (dunit (le_real_execution_observable x s)) d_le_fs_shadow_branch_choice
  (dunit_ll (le_real_execution_observable x s))).
by [].
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

lemma A_LE_fs_shadow_semantic_post_marginal_sdist_le_bad_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_fs_shadow_semantic_post_marginal x s)
      (d_le_post_fs_programmed_view x s)
      <= le_fs_shadow_local_bad_branch_mass.
proof.
move=> x s.
rewrite (d_le_fs_shadow_semantic_post_marginal_fixed_branch_imageE x s).
rewrite (d_le_post_fs_programmed_view_fixed_branch_imageE x s).
pose F := fun bad =>
  le_fs_shadow_semantic_branch_image_of_observable
    (le_real_execution_observable x s) bad.
have Hmap :
  sdist (dmap d_le_fs_shadow_branch_choice F) (dmap (dunit false) F) <=
  sdist d_le_fs_shadow_branch_choice (dunit false).
  exact (sdist_dmap d_le_fs_shadow_branch_choice (dunit false) F).
exact (ler_trans _ _ _ Hmap
  le_fs_shadow_branch_choice_sdist_dunit_false_le_bad_branch_mass).
qed.

lemma le_real_execution_observable_in_pre_fs_programming_view
  (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_pre_fs_programming_view x s.
proof.
rewrite (d_le_pre_fs_programming_view_dunit x s).
by rewrite supp_dunit.
qed.

lemma le_fs_shadow_semantic_post_marginal_support
  (x : qssm_public_input) (s : seed)
  (obs : le_transcript_observable) (bad : bool) :
  obs \in d_le_pre_fs_programming_view x s =>
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
  exact (le_real_execution_observable_in_pre_fs_programming_view x s).
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
  exact (le_real_execution_observable_in_pre_fs_programming_view x s).
exact le_fs_shadow_bad_branch_has_support.
qed.

lemma d_le_fs_shadow_semantic_post_marginal_supportE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  obs \in d_le_fs_shadow_semantic_post_marginal x s =>
  obs =
    (le_fs_shadow_state_of_branch_observable
       (le_real_execution_observable x s) false).`lefss_semantic_post_observable \/
  obs =
    (le_fs_shadow_state_of_branch_observable
       (le_real_execution_observable x s) true).`lefss_semantic_post_observable.
proof.
move=> Hobs.
rewrite (d_le_fs_shadow_semantic_post_marginal_pairE x s) in Hobs.
case/supp_dmap: Hobs=> -[pre_obs bad] [Hp ->].
move: Hp; rewrite supp_dprod => -[Hpre _].
have -> : pre_obs = le_real_execution_observable x s.
  exact (d_le_pre_fs_programming_view_supportE x s pre_obs Hpre).
clear Hpre.
by case: bad.
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
    dmap (d_le_fs_shadow_coupled_state x s) le_fs_shadow_semantic_bad_event =
      d_le_fs_shadow_branch_choice.
proof.
move=> x s.
rewrite (d_le_fs_shadow_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_fs_shadow_state_of_branch_observable (fst p) (snd p))
  le_fs_shadow_semantic_bad_event
  ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)).
have Hmap :
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice)
    (le_fs_shadow_semantic_bad_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_fs_shadow_state_of_branch_observable (fst p) (snd p))) =
  dmap ((d_le_pre_fs_programming_view x s) `*` d_le_fs_shadow_branch_choice) snd.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs bad /=.
  by rewrite /(\o) (le_fs_shadow_semantic_bad_event_branch_stateE obs bad).
rewrite Hmap.
exact (le_fs_shadow_dmap_dprod_snd_lossless
  (d_le_pre_fs_programming_view x s) d_le_fs_shadow_branch_choice
  (d_le_pre_fs_programming_view_lossless x s)).
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