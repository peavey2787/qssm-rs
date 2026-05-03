require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceModel SourceTypes SourcePayloadDistributions SourceExecutionLink.
require import SourceRealExecutionGameLink.

(* MS-3a concrete real execution-seed packaging boundary.

   This theory packages the concrete execution-facing seed law supplied by
   `SourceRealExecutionGameLink.ec`, without changing the current abstract
   source interfaces.

   Dependency direction is intentional:
   - may depend on `SourcePayloadDistributions.ec`, `SourceExecutionLink.ec`,
     and `SourceRealExecutionGameLink.ec`
   - may later be imported by `SourceProgrammedObligations.ec`
   - must not be imported by `SourcePayloadDistributions.ec`, to avoid a cycle
   - the next phase can wire `d_ms3a_real_payload_seed` to this law, or prove
     them equal, and then reuse the bridge lemma below to recover
     `ms3a_execution_public_spine_link` *)

axiom A_ms3a_real_payload_seed_matches_execution_seed :
  forall (x : ms_public_input),
    d_ms3a_real_payload_seed x =
    d_ms3a_real_execution_public_seed x.

pred ms3a_real_execution_seed_link (x : ms_public_input) =
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x) /\
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_execution_public_seed x =>
    sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
    sigma.`ms3rp_bits = ms3a_public_bits x /\
    sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.

lemma ms3a_real_execution_seed_link_of_game_execution :
  forall (x : ms_public_input),
    ms3a_real_execution_seed_link x.
proof.
move=> x; split.
- exact (ms3a_game_public_spine_programmed x).
- move=> sigma Hsig.
  exact (ms3a_game_real_execution_seed_public_fields x sigma Hsig).
qed.

lemma ms3a_public_payload_bitness_programmed_of_real_execution_seed_link
  (x : ms_public_input) :
  ms3a_real_execution_seed_link x =>
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
by move=> [Hprog _].
qed.

lemma ms3a_real_seed_public_fields_on_support_of_real_execution_seed_link
  (x : ms_public_input) :
  ms3a_real_execution_seed_link x =>
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_execution_public_seed x =>
    sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
    sigma.`ms3rp_bits = ms3a_public_bits x /\
    sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.
proof.
by move=> [_ Hlink] sigma Hsig; exact (Hlink sigma Hsig).
qed.

lemma ms3a_public_payload_bitness_programmed_of_execution_seed_law
  (x : ms_public_input) :
  ms3a_real_execution_seed_link x =>
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
exact (ms3a_public_payload_bitness_programmed_of_real_execution_seed_link x).
qed.

lemma ms3a_real_seed_public_fields_on_support_of_execution_seed_law
  (x : ms_public_input) :
  ms3a_real_execution_seed_link x =>
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
    sigma.`ms3rp_bits = ms3a_public_bits x /\
    sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.
proof.
move=> Hlink sigma Hsig.
have Hseed :=
  ms3a_real_seed_public_fields_on_support_of_real_execution_seed_link x Hlink.
rewrite (A_ms3a_real_payload_seed_matches_execution_seed x) in Hsig.
exact (Hseed sigma Hsig).
qed.

lemma ms3a_execution_public_spine_link_of_real_execution_seed_law
  (x : ms_public_input) :
  d_ms3a_real_payload_seed x = d_ms3a_real_execution_public_seed x =>
  ms3a_real_execution_seed_link x =>
  ms3a_execution_public_spine_link x.
proof.
move=> Heq [Hprog Hlink].
split=> // sigma Hsig.
rewrite Heq in Hsig.
exact (Hlink sigma Hsig).
qed.

lemma ms3a_execution_public_spine_link_of_execution_seed_law
  (x : ms_public_input) :
  ms3a_real_execution_seed_link x =>
  ms3a_execution_public_spine_link x.
proof.
move=> Hlink.
apply: (ms3a_execution_public_spine_link_of_real_execution_seed_law x).
- exact (A_ms3a_real_payload_seed_matches_execution_seed x).
exact Hlink.
qed.