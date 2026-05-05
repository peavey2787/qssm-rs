require import AllCore.
require import QssmTypes SourceTypes MS LERealExecution LESurface LEModel.
require export SourceModel.
require import SourceDistributions MSProbabilitySurface.

(* Public-only simulator interfaces *)
op ms_simulator : ms_public_input -> seed -> ms_transcript_observable.
op le_simulator : le_public_input -> seed -> le_transcript_observable.

op extract_le_public : qssm_public_input -> le_public_input.

op qssm_real_view (x : qssm_public_input) (s : seed) : qssm_public_view =
  {| qssmpv_statement_digest =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_statement_digest;
     qssmpv_result_bit =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_result_bit;
     qssmpv_bitness_global_challenges =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_bitness_global_challenges;
     qssmpv_comparison_global_challenge =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_comparison_global_challenge;
     qssmpv_comparison_openings =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_comparison_openings;
     qssmpv_transcript_digest =
       (ms3a_public_v2_observable (extract_ms_public x)).`msv2_transcript_digest;
     qssmpv_event_payload =
       qssm_event_payload_of_ms_public (extract_ms_public x);
     qssmpv_commitment_coeffs =
       (le_real_execution_observable x s).`leto_commitment_coeffs;
     qssmpv_t_coeffs =
       (le_real_execution_observable x s).`leto_t_coeffs;
     qssmpv_z_coeffs =
       (le_real_execution_observable x s).`leto_z_coeffs;
     qssmpv_challenge_seed_obs =
       (le_real_execution_observable x s).`leto_challenge_seed_obs;
     qssmpv_programmed_query_digest_obs =
       (le_real_execution_observable x s).`leto_programmed_query_digest_obs;
     qssmpv_query_material =
       (le_real_execution_observable x s).`leto_query_material;
  |}.

lemma qssm_real_view_projects_to_ms (x : qssm_public_input) (s : seed) :
  qssm_view_to_ms_observable (qssm_real_view x s) =
  ms3a_public_v2_observable (extract_ms_public x).
proof.
by rewrite /qssm_view_to_ms_observable /qssm_real_view /ms3a_public_v2_observable.
qed.

lemma qssm_real_view_projects_to_le (x : qssm_public_input) (s : seed) :
  qssm_view_to_le_observable (qssm_real_view x s) =
  le_real_execution_observable x s.
proof.
by rewrite /qssm_view_to_le_observable /qssm_real_view
  /le_real_execution_observable /le_real_execution_qssm_event_payload.
qed.

lemma qssm_real_view_projects_preserve_event_payload (x : qssm_public_input) (s : seed) :
  ms_qssm_event_payload (qssm_view_to_ms_observable (qssm_real_view x s)) =
  le_qssm_event_payload (qssm_view_to_le_observable (qssm_real_view x s)).
proof.
rewrite qssm_view_to_ms_observable_preserves_event_payload.
rewrite qssm_view_to_le_observable_preserves_event_payload.
by [].
qed.

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
