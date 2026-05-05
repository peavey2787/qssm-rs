require import AllCore List.
require ActionOwner ScalarOwner.

clone export ScalarOwner.ScalarRing as SchScalarRing.

(* Core abstract data *)
type digest.
type scalar = ScalarOwner.scalar.
type sch_point = ActionOwner.point.
type seed.
type coeff_vector = int list.

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
type le_query_material = {
	leqm_row_challenge_seed : digest;
	leqm_row_programmed_query_digest : digest;
	leqm_programmed_response_digest : digest;
	leqm_programming_log : digest list;
	leqm_bad_flag : bool;
}.

(* Transcript observables *)
type qssm_event_payload = {
	qsep_statement_digest : digest;
	qsep_result_bit : bool;
	qsep_bitness_global_challenges : digest list;
	qsep_comparison_global_challenge : digest;
	qsep_comparison_openings : ms_comparison_openings;
	qsep_transcript_digest : digest;
}.

type ms_transcript_observable = {
	msv2_statement_digest : digest;
	msv2_result_bit : bool;
	msv2_bitness_global_challenges : digest list;
	msv2_comparison_global_challenge : digest;
	msv2_comparison_openings : ms_comparison_openings;
	msv2_transcript_digest : digest;
	msv2_qssm_event_payload : qssm_event_payload;
}.
type le_transcript_observable = {
	leto_commitment_coeffs : coeff_vector;
	leto_t_coeffs : coeff_vector;
	leto_z_coeffs : coeff_vector;
	leto_challenge_seed_obs : digest;
	leto_programmed_query_digest_obs : digest;
	leto_query_material : le_query_material;
	leto_qssm_event_payload : qssm_event_payload;
}.
type qssm_public_view = {
	qssmpv_statement_digest : digest;
	qssmpv_result_bit : bool;
	qssmpv_bitness_global_challenges : digest list;
	qssmpv_comparison_global_challenge : digest;
	qssmpv_comparison_openings : ms_comparison_openings;
	qssmpv_transcript_digest : digest;
	qssmpv_event_payload : qssm_event_payload;
	qssmpv_commitment_coeffs : coeff_vector;
	qssmpv_t_coeffs : coeff_vector;
	qssmpv_z_coeffs : coeff_vector;
	qssmpv_challenge_seed_obs : digest;
	qssmpv_programmed_query_digest_obs : digest;
	qssmpv_query_material : le_query_material;
}.

op qssm_observable_event_payload (p : qssm_event_payload) : qssm_event_payload =
	{| qsep_statement_digest = p.`qsep_statement_digest;
	   qsep_result_bit = p.`qsep_result_bit;
	   qsep_bitness_global_challenges = p.`qsep_bitness_global_challenges;
	   qsep_comparison_global_challenge = p.`qsep_comparison_global_challenge;
	   qsep_comparison_openings = witness;
	   qsep_transcript_digest = p.`qsep_transcript_digest |}.

type qssm_transcript_observable.

(* Distinguishers / game views *)
type distinguisher.

op qssm_distinguisher_event (D : distinguisher) : qssm_event_payload -> bool.
