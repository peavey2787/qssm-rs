require import AllCore.
require import QssmTypes SourceTypes MS LESurface LEModel.
require import SourceDistributions MSProbabilitySurface.

(* Public-only simulator interfaces *)
op ms_simulator : ms_public_input -> seed -> ms_transcript_observable.
op le_simulator : le_public_input -> seed -> le_transcript_observable.

op extract_ms_public : qssm_public_input -> ms_public_input.
op extract_le_public : qssm_public_input -> le_public_input.

(* Canonical composed simulator entry point *)
op simulate_qssm_transcript :
  qssm_public_input -> seed -> qssm_transcript_observable.

(* Public extraction bridge: the extracted MS public surface is the MS-side
   view of the same QSSM public input that drives the LE real view. *)
axiom A_extract_ms_public_real_view_probability_eq :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    ms_view_distinguish_pr
      (d_ms3a_bitness_real_observable_v2 (extract_ms_public x)) D =
    le_view_distinguish_pr (d_le_real_view x s) D.
