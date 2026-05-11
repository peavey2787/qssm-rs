require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceModel SourceTypes SourcePayloadDistributions.

(* MS-3a execution/link boundary.

   This theory names the smallest source-facing package that future execution/game
   semantics should prove, without changing the current source interfaces.

   Dependency direction is intentional:
   - may depend on `SourcePayloadDistributions.ec` and `SourceModel.ec`
   - may later be imported by `SourceProgrammedObligations.ec`
   - must not be imported by `SourcePayloadDistributions.ec`, to avoid a cycle
   - game files should target this boundary directly rather than importing
     source theorem packaging. *)

pred ms3a_execution_public_spine_link (x : ms_public_input) =
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x) /\
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
    sigma.`ms3rp_bits = ms3a_public_bits x /\
    sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.

lemma ms3a_public_payload_bitness_programmed_of_execution_link
  (x : ms_public_input) :
  ms3a_execution_public_spine_link x =>
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
by move=> [Hprog _].
qed.

lemma ms3a_real_seed_public_fields_on_support_of_execution_link
  (x : ms_public_input) :
  ms3a_execution_public_spine_link x =>
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
    sigma.`ms3rp_bits = ms3a_public_bits x /\
    sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.
proof.
by move=> [_ Hlink] sigma Hsig; exact (Hlink sigma Hsig).
qed.
