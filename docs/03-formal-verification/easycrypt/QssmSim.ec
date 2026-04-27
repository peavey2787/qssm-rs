require import QssmTypes QssmMS QssmLE.

theory QssmSim.

(* Public-only simulator interfaces *)
op ms_simulator : ms_public_input -> seed -> ms_transcript_observable.
op le_simulator : le_public_input -> seed -> le_transcript_observable.

op extract_ms_public : qssm_public_input -> ms_public_input.
op extract_le_public : qssm_public_input -> le_public_input.

(* Canonical composed simulator entry point *)
op simulate_qssm_transcript :
  qssm_public_input -> seed -> qssm_transcript_observable.

axiom simulate_qssm_transcript_public_only :
  forall (x : qssm_public_input) (s : seed), True.

end.
