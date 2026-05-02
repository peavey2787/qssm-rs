require import AllCore List Distr.
require import QssmTypes FS.
require import SchnorrBranch.
require import BitnessOne BitnessVector TranscriptObservable.
require import TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem.

(* MS v2 transcript observable surface (abstract, aligned to execution spec). *)
op ms_statement_digest : ms_transcript_observable -> digest.
op ms_result_bit : ms_transcript_observable -> bool.
op ms_bitness_global_challenges : ms_transcript_observable -> digest list.
op ms_comparison_global_challenge : ms_transcript_observable -> digest.
op ms_transcript_digest : ms_transcript_observable -> digest.

(* ------------------------------------------------------------------------- *)
(* MS-3a public spine: six field projections from `ms_public_input`, aligned  *)
(* to `ms3a_{real,sim}_payload_seed` / v2 observable surface (`SourceTypes`). *)
(* Uninterpreted `op`s only — future seed laws / games may assume equalities   *)
(* tying these to sampled seeds; no axioms bundled here.                      *)

op ms3a_public_stmt_digest (x : ms_public_input) : digest.
op ms3a_public_result_bit (x : ms_public_input) : bool.
op ms3a_public_bits (x : ms_public_input) : ms_single_bit_or_transcript list.
op ms3a_public_bitness_globals (x : ms_public_input) : digest list.
op ms3a_public_comparison_global (x : ms_public_input) : digest.
op ms3a_public_transcript_digest (x : ms_public_input) : digest.

(* Abstract observable agrees with the canonical v2 record (linking layer).   *)
pred ms_abstract_observable_aligns_v2
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  ms_statement_digest obs = o.`msv2_statement_digest /\
  ms_result_bit obs = o.`msv2_result_bit /\
  ms_bitness_global_challenges obs = o.`msv2_bitness_global_challenges /\
  ms_comparison_global_challenge obs = o.`msv2_comparison_global_challenge /\
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
     msv2_transcript_digest = td |}.

(* Length / digest-cell shape on the public spine (no ROM or per-bit programming). *)
pred ms3a_public_bitness_shape_ok (x : ms_public_input) =
  ms_bitness_vector_length_ok (ms3a_public_bits x) /\
  ms_bitness_global_challenge_vector_length_ok (ms3a_public_bitness_globals x).

pred ms3a_public_transcript_shape_ok (x : ms_public_input) =
  ms_transcript_digest_of_observable
    (ms3a_pack_observable (ms3a_public_stmt_digest x) (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x) (ms3a_public_comparison_global x)
      (ms3a_public_transcript_digest x)).

(* Projection from canonical v2 observable to abstract observable carrier.      *)
op ms3a_observable_of_v2 : ms_v2_transcript_observable -> ms_transcript_observable.

axiom A_ms3a_observable_of_v2_aligns :
  forall (o : ms_v2_transcript_observable),
    ms_abstract_observable_aligns_v2 (ms3a_observable_of_v2 o) o.

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
op ms3a_pack_observable_with_digest
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) : ms_v2_transcript_observable.

axiom ms3a_pack_observable_with_digest_field_correct
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob =
  ms3a_pack_observable stmt rbit bitness_glob comp_glob
    (ms_transcript_digest_public_fields
      (ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob)).

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
