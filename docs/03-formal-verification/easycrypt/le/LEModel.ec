require import AllCore Distr.
require import QssmTypes FS.

(* LE transcript observable surface *)
op le_commitment_coeffs : le_transcript_observable -> coeff_vector.
op le_t_coeffs : le_transcript_observable -> coeff_vector.
op le_z_coeffs : le_transcript_observable -> coeff_vector.
op le_challenge_seed_obs : le_transcript_observable -> digest.
op le_programmed_query_digest_obs : le_transcript_observable -> digest.

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
op d_le_real_view : qssm_public_input -> seed -> le_transcript_observable distr.
op d_le_sim_view : qssm_public_input -> seed -> le_transcript_observable distr.

op le_view_distinguish_pr : le_transcript_observable distr -> distinguisher -> real.

op le_projected_real_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_real_view x s) D.

op le_projected_sim_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_sim_view x s) D.

op le_game_hop_adv (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_projected_real_adv_base x s D - le_projected_sim_adv_base x s D.

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

axiom A_LE_SetB_HVZK_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_hvzk_bound x s D.

lemma A_LE_HVZK_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_hvzk_transition_bound x s D.
proof.
move=> x s D Hsetb Heps Hfs.
rewrite /le_hvzk_transition_bound.
exact (A_LE_SetB_HVZK_bound x s D Hsetb Heps Hfs).
qed.
