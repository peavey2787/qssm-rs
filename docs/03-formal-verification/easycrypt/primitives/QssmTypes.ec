require import AllCore List.

(* Core abstract data *)
type digest.
type scalar.
type sch_point.
type seed.
type coeff_vector.

type ms_comparison_opening = sch_point * scalar.

type ms_comparison_openings = {
	mscos_true_opening : ms_comparison_opening;
	mscos_false_openings : ms_comparison_opening list;
}.

type ms_comparison_false_entry = {
	mscfe_clause_ix : int;
	mscfe_opening : ms_comparison_opening;
}.

type ms_comparison_slice = {
	mscs_true_clause_ix : int;
	mscs_true_opening : ms_comparison_opening;
	mscs_false_entries : ms_comparison_false_entry list;
}.

(* Public input surface *)
type le_public_input.
type qssm_public_input.

(* Query material *)
type ms_bitness_query.
type ms_comparison_query.
type le_query_material.

(* Transcript observables *)
type ms_transcript_observable = {
	msv2_statement_digest : digest;
	msv2_result_bit : bool;
	msv2_bitness_global_challenges : digest list;
	msv2_comparison_global_challenge : digest;
	msv2_comparison_openings : ms_comparison_openings;
	msv2_transcript_digest : digest;
}.
type le_transcript_observable = {
	leto_commitment_coeffs : coeff_vector;
	leto_t_coeffs : coeff_vector;
	leto_z_coeffs : coeff_vector;
	leto_challenge_seed_obs : digest;
	leto_programmed_query_digest_obs : digest;
	leto_query_material : le_query_material;
}.
type qssm_transcript_observable.

(* Distinguishers / game views *)
type distinguisher.
