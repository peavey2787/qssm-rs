require import AllCore.
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
op le_game_hop_adv : qssm_public_input -> seed -> distinguisher -> real.

pred le_real_sim_transcript_equiv (x : qssm_public_input) (s : seed) =
  exists (obsr obss : le_transcript_observable),
    le_commitment_coeffs obsr = le_commitment_coeffs obss /\
    le_t_coeffs obsr = le_t_coeffs obss /\
    le_z_coeffs obsr = le_z_coeffs obss /\
    le_challenge_seed_obs obsr = le_challenge_seed_obs obss /\
    le_programmed_query_digest_obs obsr = le_programmed_query_digest_obs obss.

pred le_hvzk_transition_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_game_hop_adv x s D <= epsilon_le.

axiom A_LE_HVZK_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_hvzk_transition_bound x s D.
