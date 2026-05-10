require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceModel SourceTypes SourceConstructors SourcePayloadDistributions.
require import SourceExecutionLink SourcePublicBitnessExecution.
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

(* The real payload-seed law is now definitionally a `dmap` of a `dunit` at the canonical
   public spine (`SourcePayloadDistributions.ec`), and `d_ms3a_real_execution_public_seed`
   here is the same `dmap` of a `dunit` at `ms3a_game_public_bitness_source` (which unfolds
   to the same `ms3a_make_real_source` record). The bridge therefore reduces to a
   definitional equality. *)
lemma A_ms3a_real_payload_seed_matches_execution_seed (x : ms_public_input) :
  d_ms3a_real_payload_seed x =
  d_ms3a_real_execution_public_seed x.
proof.
rewrite /d_ms3a_real_payload_seed /d_ms3a_real_execution_public_seed
        /d_ms3a_real_execution_bitness_source /ms3a_game_public_bitness_source.
by [].
qed.

lemma ms3a_game_public_bitness_source_on_spine_support
  (x : ms_public_input) (s : seed) :
  ms3a_game_public_bitness_source x \in d_ms3a_seed_spine_joint x s.
proof.
pose sigma :=
  ms3a_real_payload_seed_of_bitness_layer (ms3a_game_public_bitness_source x).
have Hexec : sigma \in d_ms3a_real_execution_public_seed x.
- rewrite /sigma /d_ms3a_real_execution_public_seed
    /d_ms3a_real_execution_bitness_source.
  apply/supp_dmap.
  exists (ms3a_game_public_bitness_source x).
  split.
  + by rewrite supp_dunit.
  by [].
have Hreal : sigma \in d_ms3a_real_payload_seed x.
- move: Hexec.
  by rewrite -(A_ms3a_real_payload_seed_matches_execution_seed x).
rewrite -(A_ms3a_spine_real_marginal_matches_seed x s) in Hreal.
case/supp_dmap: Hreal=> src [Hsrc Hsigma].
have Hsrc_eq : ms3a_game_public_bitness_source x = src.
- move: Hsigma.
  rewrite /sigma => Hsigma.
  have Hlift :
    ms3a_bitness_layer_source_of_real_payload
      (ms3a_real_payload_seed_of_bitness_layer (ms3a_game_public_bitness_source x)) =
    ms3a_bitness_layer_source_of_real_payload
      (ms3a_real_payload_seed_of_bitness_layer src).
  - by rewrite Hsigma.
  move: Hlift.
  by rewrite !L_ms3a_bitness_layer_of_real_payload_seed_of_bitness.
move: Hsrc.
by rewrite -Hsrc_eq.
qed.

lemma ms3a_game_public_bitness_source_wf
  (x : ms_public_input) :
  ms3a_source_wf (ms3a_game_public_bitness_source x).
proof.
have Hsupp := ms3a_game_public_bitness_source_on_spine_support x witness.
exact (A_ms3a_seed_spine_support_wf x witness
  (ms3a_game_public_bitness_source x) Hsupp).
qed.

lemma ms3a_public_bits_per_bit_programmed_of_game_execution
  (x : ms_public_input) :
  ms_per_bit_programmed
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x).
proof.
move: (ms3a_game_public_bitness_source_wf x).
rewrite /ms3a_source_wf /ms3a_game_public_bitness_source
  /ms3a_make_real_source /ms_bitness_vector_programmed_layer /=.
by move=> [Hper _].
qed.

lemma ms3a_public_bitness_globals_ordered_of_game_execution
  (x : ms_public_input) :
  ms_ordered_challenge_vector_matches
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
move: (ms3a_game_public_bitness_source_wf x).
rewrite /ms3a_source_wf /ms3a_game_public_bitness_source
  /ms3a_make_real_source /ms_bitness_vector_programmed_layer /=.
by move=> [_ Hord].
qed.

lemma ms3a_public_bitness_execution_of_game_execution
  (x : ms_public_input) :
  ms3a_public_bitness_execution x.
proof.
move: (ms3a_game_public_bitness_source_wf x).
rewrite /ms3a_source_wf /ms3a_game_public_bitness_source
  /ms3a_make_real_source /ms_bitness_vector_programmed_layer /=.
move=> [Hper Hord].
rewrite /ms3a_public_bitness_execution.
split.
- move: Hord.
  rewrite /ms_ordered_challenge_vector_matches /ms3a_public_bitness_shape_ok.
  by move=> [Hlen_bits [Hlen_glob _]]; split.
split.
- exact Hper.
move: Hord; rewrite /ms_ordered_challenge_vector_matches.
by move=> [_ [_ Hglob]].
qed.

lemma ms3a_public_bitness_vector_programmed_of_game_execution
  (x : ms_public_input) :
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
exact (ms3a_public_bitness_vector_programmed_of_public_bitness_execution x
  (ms3a_public_bitness_execution_of_game_execution x)).
qed.

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
- exact (ms3a_public_bitness_vector_programmed_of_game_execution x).
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
split.
- exact Hprog.
move=> sigma Hsig.
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