require import AllCore.
require import QssmTypes QssmFS.

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

(* Checker-friendly placeholder; replace with numeric ineq once Int order is wired *)
axiom set_b_parameter_well_formed : true.

op epsilon_le : real.

(* A4 placeholder *)
axiom A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.
