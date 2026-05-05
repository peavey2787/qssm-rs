require import AllCore List Distr.
require import Domains QssmTypes SourceTypes FS.
require import SchnorrBranch.
require import BitnessOne BitnessVector TranscriptObservable.
require import TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem.

op extract_ms_public : qssm_public_input -> ms_public_input.

(* MS v2 transcript observable surface, now concrete via the base observable record. *)
op ms_statement_digest (obs : ms_transcript_observable) : digest =
  obs.`msv2_statement_digest.

op ms_result_bit (obs : ms_transcript_observable) : bool =
  obs.`msv2_result_bit.

op ms_bitness_global_challenges (obs : ms_transcript_observable) : digest list =
  obs.`msv2_bitness_global_challenges.

op ms_comparison_global_challenge (obs : ms_transcript_observable) : digest =
  obs.`msv2_comparison_global_challenge.

op ms_comparison_openings (obs : ms_transcript_observable) : ms_comparison_openings =
  obs.`msv2_comparison_openings.

op ms_transcript_digest (obs : ms_transcript_observable) : digest =
  obs.`msv2_transcript_digest.

op ms_qssm_event_payload (obs : ms_transcript_observable) : qssm_event_payload =
  obs.`msv2_qssm_event_payload.

(* ------------------------------------------------------------------------- *)
(* MS-3a public spine: concrete projections from the base-layer public record. *)

op ms3a_public_stmt_digest (x : ms_public_input) : digest = x.`mspi_stmt_digest.

op ms3a_public_result_bit (x : ms_public_input) : bool = x.`mspi_result_bit.

op ms3a_public_bit_at (x : ms_public_input) (i : int) : ms_single_bit_or_transcript =
  ms_public_bit_transcript x i.

op ms3a_public_bits (x : ms_public_input) : ms_single_bit_or_transcript list =
  [ ms3a_public_bit_at x 0;  ms3a_public_bit_at x 1;  ms3a_public_bit_at x 2;
    ms3a_public_bit_at x 3;  ms3a_public_bit_at x 4;  ms3a_public_bit_at x 5;
    ms3a_public_bit_at x 6;  ms3a_public_bit_at x 7;  ms3a_public_bit_at x 8;
    ms3a_public_bit_at x 9;  ms3a_public_bit_at x 10; ms3a_public_bit_at x 11;
    ms3a_public_bit_at x 12; ms3a_public_bit_at x 13; ms3a_public_bit_at x 14;
    ms3a_public_bit_at x 15; ms3a_public_bit_at x 16; ms3a_public_bit_at x 17;
    ms3a_public_bit_at x 18; ms3a_public_bit_at x 19; ms3a_public_bit_at x 20;
    ms3a_public_bit_at x 21; ms3a_public_bit_at x 22; ms3a_public_bit_at x 23;
    ms3a_public_bit_at x 24; ms3a_public_bit_at x 25; ms3a_public_bit_at x 26;
    ms3a_public_bit_at x 27; ms3a_public_bit_at x 28; ms3a_public_bit_at x 29;
    ms3a_public_bit_at x 30; ms3a_public_bit_at x 31; ms3a_public_bit_at x 32;
    ms3a_public_bit_at x 33; ms3a_public_bit_at x 34; ms3a_public_bit_at x 35;
    ms3a_public_bit_at x 36; ms3a_public_bit_at x 37; ms3a_public_bit_at x 38;
    ms3a_public_bit_at x 39; ms3a_public_bit_at x 40; ms3a_public_bit_at x 41;
    ms3a_public_bit_at x 42; ms3a_public_bit_at x 43; ms3a_public_bit_at x 44;
    ms3a_public_bit_at x 45; ms3a_public_bit_at x 46; ms3a_public_bit_at x 47;
    ms3a_public_bit_at x 48; ms3a_public_bit_at x 49; ms3a_public_bit_at x 50;
    ms3a_public_bit_at x 51; ms3a_public_bit_at x 52; ms3a_public_bit_at x 53;
    ms3a_public_bit_at x 54; ms3a_public_bit_at x 55; ms3a_public_bit_at x 56;
    ms3a_public_bit_at x 57; ms3a_public_bit_at x 58; ms3a_public_bit_at x 59;
    ms3a_public_bit_at x 60; ms3a_public_bit_at x 61; ms3a_public_bit_at x 62;
    ms3a_public_bit_at x 63 ].

op ms3a_public_bitness_global_at (x : ms_public_input) (i : int) : digest =
  ms_public_bit_global_digest x i.

op ms3a_public_bitness_globals (x : ms_public_input) : digest list =
  ms_public_bitness_global_digests x.

op ms3a_public_comparison_global (x : ms_public_input) : digest =
  x.`mspi_comparison_global.

op ms3a_public_comparison_slice (x : ms_public_input) : ms_comparison_slice =
  ms_public_comparison_slice x.

op ms3a_public_comparison_openings (x : ms_public_input) : ms_comparison_openings =
  {| mscos_true_opening = ms_public_comparison_true_opening x;
     mscos_false_openings = ms_public_comparison_false_openings x |}.

(* Source-model boundary note: this interface stops at the native public
  comparison openings carried by `ms_public_input` / `ms_transcript_observable`.
  Richer non-public comparison execution bundles, such as the MS-3c execution
  seed's ROM row and transcript-opening package, stay below this layer unless a
  future source/game obligation requires them explicitly. *)

op ms3a_public_transcript_digest (x : ms_public_input) : digest =
  ms_public_transcript_digest_canonical x.

op qssm_event_payload_of_ms_fields
  (stmt : digest) (rbit : bool) (bitness_glob : digest list)
  (comp_glob : digest) (comp_openings : ms_comparison_openings)
  (td : digest) : qssm_event_payload =
  {| qsep_statement_digest = stmt;
     qsep_result_bit = rbit;
     qsep_bitness_global_challenges = bitness_glob;
     qsep_comparison_global_challenge = comp_glob;
     qsep_comparison_openings = comp_openings;
     qsep_transcript_digest = td |}.

op qssm_event_payload_of_ms_public (x : ms_public_input) : qssm_event_payload =
  qssm_event_payload_of_ms_fields
    (ms3a_public_stmt_digest x)
    (ms3a_public_result_bit x)
    (ms3a_public_bitness_globals x)
    (ms3a_public_comparison_global x)
    (ms3a_public_comparison_openings x)
    (ms3a_public_transcript_digest x).

(* Abstract observable agrees with the canonical v2 record (linking layer).   *)
pred ms_abstract_observable_aligns_v2
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  ms_statement_digest obs = o.`msv2_statement_digest /\
  ms_result_bit obs = o.`msv2_result_bit /\
  ms_bitness_global_challenges obs = o.`msv2_bitness_global_challenges /\
  ms_comparison_global_challenge obs = o.`msv2_comparison_global_challenge /\
  ms_comparison_openings obs = o.`msv2_comparison_openings /\
  ms_transcript_digest obs = o.`msv2_transcript_digest.

(* Abstract transcript + v2 record + digest cell (reusable MS-3a frame).      *)
pred ms3a_frame_consistent
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  ms_abstract_observable_aligns_v2 obs o /\
  ms_transcript_digest_of_observable o.

(* Canonical observable packer from the MS-v2 public transcript fields.         *)
op ms3a_pack_observable
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest) : ms_v2_transcript_observable =
  {| msv2_statement_digest = stmt;
     msv2_result_bit = rbit;
     msv2_bitness_global_challenges = bitness_glob;
     msv2_comparison_global_challenge = comp_glob;
    msv2_comparison_openings = witness;
    msv2_transcript_digest = td;
    msv2_qssm_event_payload =
     qssm_event_payload_of_ms_fields stmt rbit bitness_glob comp_glob witness td |}.

(* Length / digest-cell shape on the public spine (no ROM or per-bit programming). *)
pred ms3a_public_bitness_shape_ok (x : ms_public_input) =
  ms_bitness_vector_length_ok (ms3a_public_bits x) /\
  ms_bitness_global_challenge_vector_length_ok (ms3a_public_bitness_globals x).

pred ms3a_public_transcript_shape_ok (x : ms_public_input) =
  ms_transcript_digest_of_observable
    {| msv2_statement_digest = ms3a_public_stmt_digest x;
       msv2_result_bit = ms3a_public_result_bit x;
       msv2_bitness_global_challenges = ms3a_public_bitness_globals x;
       msv2_comparison_global_challenge = ms3a_public_comparison_global x;
       msv2_comparison_openings = ms3a_public_comparison_openings x;
       msv2_transcript_digest = ms3a_public_transcript_digest x;
       msv2_qssm_event_payload = qssm_event_payload_of_ms_public x |}.

op ms3a_public_v2_observable (x : ms_public_input) : ms_v2_transcript_observable =
  {| msv2_statement_digest = ms3a_public_stmt_digest x;
     msv2_result_bit = ms3a_public_result_bit x;
     msv2_bitness_global_challenges = ms3a_public_bitness_globals x;
     msv2_comparison_global_challenge = ms3a_public_comparison_global x;
     msv2_comparison_openings = ms3a_public_comparison_openings x;
     msv2_transcript_digest = ms3a_public_transcript_digest x;
     msv2_qssm_event_payload = qssm_event_payload_of_ms_public x |}.

op qssm_view_to_ms_observable (v : qssm_public_view) : ms_v2_transcript_observable =
  {| msv2_statement_digest = v.`qssmpv_statement_digest;
     msv2_result_bit = v.`qssmpv_result_bit;
     msv2_bitness_global_challenges = v.`qssmpv_bitness_global_challenges;
     msv2_comparison_global_challenge = v.`qssmpv_comparison_global_challenge;
     msv2_comparison_openings = v.`qssmpv_comparison_openings;
     msv2_transcript_digest = v.`qssmpv_transcript_digest;
     msv2_qssm_event_payload = v.`qssmpv_event_payload |}.

lemma ms3a_public_v2_observable_preserves_event_payload (x : ms_public_input) :
  ms_qssm_event_payload (ms3a_public_v2_observable x) =
  qssm_event_payload_of_ms_public x.
proof.
by rewrite /ms_qssm_event_payload /ms3a_public_v2_observable.
qed.

lemma qssm_view_to_ms_observable_preserves_event_payload (v : qssm_public_view) :
  ms_qssm_event_payload (qssm_view_to_ms_observable v) =
  v.`qssmpv_event_payload.
proof.
by rewrite /ms_qssm_event_payload /qssm_view_to_ms_observable.
qed.

(* Projection from canonical v2 observable to the observable carrier. Since the
   carrier now uses the same concrete record, this is the identity map.        *)
op ms3a_observable_of_v2 (o : ms_v2_transcript_observable) : ms_transcript_observable =
  o.

lemma A_ms3a_observable_of_v2_aligns :
  forall (o : ms_v2_transcript_observable),
    ms_abstract_observable_aligns_v2 (ms3a_observable_of_v2 o) o.
proof.
move=> o.
rewrite /ms_abstract_observable_aligns_v2 /ms3a_observable_of_v2.
rewrite /ms_statement_digest /ms_result_bit /ms_bitness_global_challenges.
rewrite /ms_comparison_global_challenge /ms_comparison_openings /ms_transcript_digest.
by split=> //; split=> //; split=> //; split=> //; split.
qed.

(* ROM/FS-side programmability of the MS-3a public spine.

   This is the canonical ROM/FS-layer assumption that the abstract `ms3a_public_*`
   outputs (above) are produced by an honest programmed bitness execution: per-bit FS
   programmability + ordered global-challenge alignment. It lives at the source-model
   layer because that is where `ms3a_public_*` are declared, and it is the single
   primitive carrying the `ms_bitness_vector_programmed_layer` fact about the public
   spine; the previous source-distribution-level axiom
   `A_ms3a_seed_spine_support_wf` (`ms/source/SourcePayloadDistributions.ec`) is now a
   proved lemma derived from this one. No new axiom is introduced overall: this is the
   same logical content moved to its proper layer next to the abstract source model
   (which already imports `FS` and `BitnessVector`). *)
lemma ms3a_public_bits_nth_valid (x : ms_public_input) (i : int) :
  ms_bit_index_valid i =>
  ms_nth_single_bit_or (ms3a_public_bits x) i = ms3a_public_bit_at x i.
proof.
move=> Hi.
have Hcases :
  i = 0  \/ i = 1  \/ i = 2  \/ i = 3  \/ i = 4  \/ i = 5  \/ i = 6  \/ i = 7  \/
  i = 8  \/ i = 9  \/ i = 10 \/ i = 11 \/ i = 12 \/ i = 13 \/ i = 14 \/ i = 15 \/
  i = 16 \/ i = 17 \/ i = 18 \/ i = 19 \/ i = 20 \/ i = 21 \/ i = 22 \/ i = 23 \/
  i = 24 \/ i = 25 \/ i = 26 \/ i = 27 \/ i = 28 \/ i = 29 \/ i = 30 \/ i = 31 \/
  i = 32 \/ i = 33 \/ i = 34 \/ i = 35 \/ i = 36 \/ i = 37 \/ i = 38 \/ i = 39 \/
  i = 40 \/ i = 41 \/ i = 42 \/ i = 43 \/ i = 44 \/ i = 45 \/ i = 46 \/ i = 47 \/
  i = 48 \/ i = 49 \/ i = 50 \/ i = 51 \/ i = 52 \/ i = 53 \/ i = 54 \/ i = 55 \/
  i = 56 \/ i = 57 \/ i = 58 \/ i = 59 \/ i = 60 \/ i = 61 \/ i = 62 \/ i = 63 by smt.
move: Hcases.
rewrite /ms_nth_single_bit_or /ms3a_public_bits /=.
move=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
by smt.
qed.

lemma ms3a_public_bitness_globals_nth_valid (x : ms_public_input) (i : int) :
  ms_bit_index_valid i =>
  nth witness (ms3a_public_bitness_globals x) i = ms3a_public_bitness_global_at x i.
proof.
move=> Hi.
have Hcases :
  i = 0  \/ i = 1  \/ i = 2  \/ i = 3  \/ i = 4  \/ i = 5  \/ i = 6  \/ i = 7  \/
  i = 8  \/ i = 9  \/ i = 10 \/ i = 11 \/ i = 12 \/ i = 13 \/ i = 14 \/ i = 15 \/
  i = 16 \/ i = 17 \/ i = 18 \/ i = 19 \/ i = 20 \/ i = 21 \/ i = 22 \/ i = 23 \/
  i = 24 \/ i = 25 \/ i = 26 \/ i = 27 \/ i = 28 \/ i = 29 \/ i = 30 \/ i = 31 \/
  i = 32 \/ i = 33 \/ i = 34 \/ i = 35 \/ i = 36 \/ i = 37 \/ i = 38 \/ i = 39 \/
  i = 40 \/ i = 41 \/ i = 42 \/ i = 43 \/ i = 44 \/ i = 45 \/ i = 46 \/ i = 47 \/
  i = 48 \/ i = 49 \/ i = 50 \/ i = 51 \/ i = 52 \/ i = 53 \/ i = 54 \/ i = 55 \/
  i = 56 \/ i = 57 \/ i = 58 \/ i = 59 \/ i = 60 \/ i = 61 \/ i = 62 \/ i = 63 by smt.
move: Hcases.
rewrite /ms3a_public_bitness_globals /ms_public_bitness_global_digests /=.
rewrite /ms3a_public_bitness_global_at.
move=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
move: Hcases=> [-> | Hcases]; first by [].
by smt.
qed.

lemma A_ms3a_public_spine_programmed_layer (x : ms_public_input) :
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
rewrite /ms_bitness_vector_programmed_layer; split.
- rewrite /ms_per_bit_programmed => i Hi.
  have -> : ms_nth_single_bit_or (ms3a_public_bits x) i = ms3a_public_bit_at x i.
    exact (ms3a_public_bits_nth_valid x i Hi).
  exact (ms_public_bit_transcript_programmed x i).
rewrite /ms_ordered_challenge_vector_matches /ms_bitness_vector_length_ok /=; split.
- by [].
split.
- by rewrite /ms_bitness_global_challenge_vector_length_ok
  /ms3a_public_bitness_globals /ms_public_bitness_global_digests /=.
move=> i Hi.
have Hglob := ms3a_public_bitness_globals_nth_valid x i Hi.
have Hbit := ms3a_public_bits_nth_valid x i Hi.
rewrite Hglob Hbit /ms3a_public_bitness_global_at /ms_public_bit_global_digest.
by rewrite /ms3a_public_bit_at /ms_public_bit_transcript /ms_pack_single_bit_or /=.
qed.

(* Frame constructor relation for packed observables.                           *)
pred ms3a_packed_frame
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest)
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  o = ms3a_pack_observable stmt rbit bitness_glob comp_glob td /\
  obs = ms3a_observable_of_v2 o /\
  ms3a_frame_consistent obs o.

lemma MS_3a_frame_consistent_of_v2
  (o : ms_v2_transcript_observable) :
  ms_transcript_digest_of_observable o =>
  ms3a_frame_consistent (ms3a_observable_of_v2 o) o.
proof.
move=> Hd; split.
- exact (A_ms3a_observable_of_v2_aligns o).
exact Hd.
qed.

(* Constructor/layout lemma: for any packed observable, digest consistency
   follows from the explicit digest-field equation. *)
lemma ms3a_packed_observable_digest_consistent
  (stmt : digest) (rbit : bool) (bitness_glob : digest list)
  (comp_glob : digest) (td : digest) :
  td = ms_transcript_digest_public_fields
        (ms3a_pack_observable stmt rbit bitness_glob comp_glob td) =>
  ms_transcript_digest_of_observable
    (ms3a_pack_observable stmt rbit bitness_glob comp_glob td).
proof.
move=> Htd; rewrite /ms_transcript_digest_of_observable /ms3a_pack_observable.
by rewrite -Htd.
qed.

(* Digest-by-construction constructor (generic, non-default-specific).        *)
op ms3a_pack_observable_with_digest_digest
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) : digest =
  hash_domain LABEL_MS_V2_PROOF
    (stmt :: ms_result_bit_digest rbit :: comp_glob :: bitness_glob).

op ms3a_pack_observable_with_digest
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) : ms_v2_transcript_observable =
  ms3a_pack_observable stmt rbit bitness_glob comp_glob
    (ms3a_pack_observable_with_digest_digest stmt rbit bitness_glob comp_glob).

lemma ms3a_public_transcript_shape_ok_implies_digest_by_construction
  (x : ms_public_input) :
  ms3a_public_transcript_shape_ok x =>
  ms3a_public_transcript_digest x =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).
proof.
rewrite /ms3a_public_transcript_shape_ok /ms_transcript_digest_of_observable.
rewrite /ms_transcript_digest_public_fields /= /ms3a_pack_observable_with_digest_digest.
rewrite /ms_result_bit_digest.
by [].
qed.

lemma ms3a_public_transcript_digest_by_construction
  (x : ms_public_input) :
  ms3a_public_transcript_digest x =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).
proof.
rewrite /ms3a_public_transcript_digest /ms_public_transcript_digest_canonical.
rewrite /ms3a_public_stmt_digest /ms3a_public_result_bit.
rewrite /ms3a_public_bitness_globals /ms3a_public_comparison_global.
rewrite /ms3a_pack_observable_with_digest_digest /ms_result_bit_digest.
by [].
qed.

lemma ms3a_public_transcript_shape_ok_iff_digest_by_construction
  (x : ms_public_input) :
  ms3a_public_transcript_shape_ok x <=>
  ms3a_public_transcript_digest x =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).
proof.
rewrite /ms3a_public_transcript_shape_ok /ms_transcript_digest_of_observable.
rewrite /ms3a_public_v2_observable /ms_transcript_digest_public_fields /=.
rewrite /ms3a_pack_observable_with_digest_digest /ms_result_bit_digest.
by [].
qed.

lemma ms3a_public_transcript_shape_ok_holds
  (x : ms_public_input) :
  ms3a_public_transcript_shape_ok x.
proof.
rewrite (ms3a_public_transcript_shape_ok_iff_digest_by_construction x).
exact (ms3a_public_transcript_digest_by_construction x).
qed.

lemma ms3a_pack_observable_with_digest_field_correct
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob =
  ms3a_pack_observable stmt rbit bitness_glob comp_glob
    (ms_transcript_digest_public_fields
      (ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob)).
proof.
rewrite /ms3a_pack_observable_with_digest.
rewrite /ms_transcript_digest_public_fields /ms3a_pack_observable /=.
rewrite /ms3a_pack_observable_with_digest_digest /ms_result_bit_digest.
by [].
qed.

lemma ms3a_pack_observable_with_digest_consistent
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms_transcript_digest_of_observable
    (ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob).
proof.
have Ho :=
  ms3a_pack_observable_with_digest_field_correct
    stmt rbit bitness_glob comp_glob.
rewrite Ho; apply ms3a_packed_observable_digest_consistent.
by rewrite -{1}Ho.
qed.
