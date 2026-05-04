require import AllCore Distr.
require import StdOrder.
require import Real.
require import SDist.
require import QssmTypes FS LERealExecution.

(*---*) import RealOrder.

(* LE transcript observable surface *)
op le_commitment_coeffs (obs : le_transcript_observable) : coeff_vector =
  obs.`leto_commitment_coeffs.

op le_t_coeffs (obs : le_transcript_observable) : coeff_vector =
  obs.`leto_t_coeffs.

op le_z_coeffs (obs : le_transcript_observable) : coeff_vector =
  obs.`leto_z_coeffs.

op le_challenge_seed_obs (obs : le_transcript_observable) : digest =
  obs.`leto_challenge_seed_obs.

op le_programmed_query_digest_obs (obs : le_transcript_observable) : digest =
  obs.`leto_programmed_query_digest_obs.

op le_fs_query_material_obs (obs : le_transcript_observable) : le_query_material =
  obs.`leto_query_material.

(* Set B parameter placeholders (concrete values live in qssm-le params.rs) *)
op C_POLY_SIZE : int.
op C_POLY_SPAN : int.
op ETA : int.
op GAMMA : int.
op BETA : int.

(* Abstract but non-vacuous Set-B well-formedness envelope. *)
pred set_b_parameter_well_formed =
  0 < C_POLY_SIZE /\
  0 < C_POLY_SPAN /\
  0 < ETA /\
  0 < GAMMA /\
  0 < BETA /\
  ETA <= GAMMA.

op epsilon_le : real.

axiom A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.

(* LE-only game-hop surface for the G1->G2 transition. *)
op d_le_real_view : qssm_public_input -> seed -> le_transcript_observable distr =
  d_le_real_execution_view.

(* Measurable transforms on the LE observable surface: rejection hop, then FS. *)
op le_post_rejection_surrogate
  (obs : le_transcript_observable) : le_transcript_observable = obs.

op le_fs_program_query_material (qmat : le_query_material) : le_query_material =
  qmat.

op le_fs_view_surrogate
  (obs : le_transcript_observable) : le_transcript_observable =
  {|
    leto_commitment_coeffs = le_commitment_coeffs obs;
    leto_t_coeffs = le_t_coeffs obs;
    leto_z_coeffs = le_z_coeffs obs;
    leto_challenge_seed_obs = le_challenge_seed_obs obs;
    leto_programmed_query_digest_obs = le_programmed_query_digest_obs obs;
    leto_query_material = le_fs_program_query_material (le_fs_query_material_obs obs);
  |}.

(* Post-rejection marginal: push-forward of the real view after the rejection-sampling
   phase and before FS programming is modeled on the sim side. *)
op d_le_post_rejection_view (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_real_view x s) le_post_rejection_surrogate.

(* Simulated LE view: FS programming as push-forward of the post-rejection view. *)
op d_le_sim_view (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_post_rejection_view x s) le_fs_view_surrogate.

(* Distinguisher as an event on LE transcript observables (interface to mu / sdist). *)
op le_distinguisher_event (D : distinguisher) : le_transcript_observable -> bool.

op le_view_distinguish_pr (d : le_transcript_observable distr) (D : distinguisher) : real =
  mu d (le_distinguisher_event D).

op le_projected_real_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_real_view x s) D.

op le_projected_sim_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_sim_view x s) D.

op le_game_hop_adv (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_projected_real_adv_base x s D - le_projected_sim_adv_base x s D.

(* Statistical distance (sdist / event-lub formulation) on projected LE views. *)
op le_view_statistical_distance (x : qssm_public_input) (s : seed) : real =
  sdist (d_le_real_view x s) (d_le_sim_view x s).

(* Game-hop / distinguisher advantage at the LE projected-view interface. *)
op le_view_distinguishing_adv (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_game_hop_adv x s D.

pred le_view_statistical_distance_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_view_statistical_distance x s <= epsilon_le.

pred le_real_sim_transcript_equiv (x : qssm_public_input) (s : seed) =
  exists (obsr obss : le_transcript_observable),
    le_commitment_coeffs obsr = le_commitment_coeffs obss /\
    le_t_coeffs obsr = le_t_coeffs obss /\
    le_z_coeffs obsr = le_z_coeffs obss /\
    le_challenge_seed_obs obsr = le_challenge_seed_obs obss /\
    le_programmed_query_digest_obs obsr = le_programmed_query_digest_obs obss.

pred le_set_b_params_ok =
  set_b_parameter_well_formed.

pred le_rejection_sampling_bound_ok =
  0%r <= epsilon_le.

pred le_fs_programming_bound_ok (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_hvzk_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_game_hop_adv x s D <= epsilon_le.

pred le_hvzk_transition_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_hvzk_bound x s D.

pred le_set_b_ring_dimension_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < C_POLY_SIZE /\ 0 < C_POLY_SPAN.

pred le_set_b_challenge_size_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < GAMMA /\ 0 < BETA.

pred le_set_b_norm_bounds_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < ETA.

pred le_set_b_eta_gamma_relation_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  ETA <= GAMMA.

pred le_set_b_params_sound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_set_b_ring_dimension_valid x s D /\
  le_set_b_challenge_size_valid x s D /\
  le_set_b_norm_bounds_valid x s D /\
  le_set_b_eta_gamma_relation_valid x s D.

pred le_rejection_sampling_hiding_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_rejection_sampling_bound_ok.

pred le_fs_programming_hiding_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_fs_programming_bound_ok x s.

pred le_real_view_distribution_defined (x : qssm_public_input) (s : seed) =
  le_set_b_params_ok.

pred le_sim_view_distribution_defined (x : qssm_public_input) (s : seed) =
  le_set_b_params_ok.
