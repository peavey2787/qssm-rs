require import AllCore.

(* Core abstract data *)
type digest.
type scalar.
type seed.
type coeff_vector.

(* Public input surface *)
type ms_public_input.
type le_public_input.
type qssm_public_input.

(* Transcript observables *)
type ms_transcript_observable.
type le_transcript_observable.
type qssm_transcript_observable.

(* Query material *)
type ms_bitness_query.
type ms_comparison_query.
type le_query_material.

(* Distinguishers / game views *)
type distinguisher.
type game_view.
