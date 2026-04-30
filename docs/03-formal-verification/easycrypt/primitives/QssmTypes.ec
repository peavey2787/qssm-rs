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

(* MS sub-game stages inside the G0→G1 hop (QSSM-level public input + seed). *)
type ms_game_stage = [
  | MSGameStageReal
  | MSGameStageAfterBinding
  | MSGameStageAfterRom
  | MSGameStageAfterBitness
  | MSGameStageAfterComparison
  | MSGameStageSim
].

(* Structured MS slice of a QSSM game view (LE slot optional for QSSM wiring). *)
type ms_game_view_record = {
  msgv_qssm_pub : qssm_public_input;
  msgv_seed : seed;
  msgv_ms_pub : ms_public_input;
  msgv_ms_obs : ms_transcript_observable;
  msgv_stage : ms_game_stage;
  msgv_le_placeholder : le_transcript_observable option;
}.

(* QSSM game views: MS-structured hops, or G2 full-sim shell (LE-heavy) for now. *)
type qssm_g2_shell_record = {
  qg2_pub : qssm_public_input;
  qg2_seed : seed;
}.

type game_view = [
  | GV_ms of ms_game_view_record
  | GV_g2_full_sim of qssm_g2_shell_record
].
