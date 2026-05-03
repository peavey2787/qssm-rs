require import AllCore List.
require import QssmTypes BitnessOne BitnessVector.
require import SourceModel.

(* MS-3a public bitness execution boundary.

   This theory centralizes the remaining ROM/FS-facing public-bitness semantic
   debt in one package predicate over the abstract public projections from
   `SourceModel.ec`. It is intentionally source-specific rather than extending
  the generic FS/bitness theories.

  Constructor-design note: `SourcePublicBitnessConstructors.ec` now names the
  concrete list-level objects `ms3a_public_bits_of_execution` and
  `ms3a_public_bitness_globals_of_execution` on
  `ms3a_bitness_layer_source`. The planned replacement path for the axiom
  below is to prove shape, ordered-global, and per-bit programmed lemmas on
  that constructor surface for the concrete game execution source, then add a
  single equality bridge back to the abstract `SourceModel.ec` projections. *)

pred ms3a_public_bitness_execution (x : ms_public_input) =
  ms3a_public_bitness_shape_ok x /\
  (forall (i : int),
    ms_bit_index_valid i =>
    let t = ms_nth_single_bit_or (ms3a_public_bits x) i in
    t.`msbt_stmt = ms3a_public_stmt_digest x /\
    ms_single_bit_programmed_bitness_transcript
      (ms3a_public_stmt_digest x) i
      t.`msbt_pub0 t.`msbt_pub1
      t.`msbt_branch0 t.`msbt_branch1
      t.`msbt_challenge_zero t.`msbt_challenge_one t.`msbt_global_challenge) /\
  (forall (i : int),
    ms_bit_index_valid i =>
    nth witness (ms3a_public_bitness_globals x) i =
      ms_bitness_challenge_scalar_digest
        (ms_nth_single_bit_or (ms3a_public_bits x) i).`msbt_global_challenge).

axiom A_ms3a_public_bitness_execution :
  forall (x : ms_public_input),
    ms3a_public_bitness_execution x.

lemma ms3a_public_bitness_vector_programmed_of_public_bitness_execution
  (x : ms_public_input) :
  ms3a_public_bitness_execution x =>
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
move=> [Hshape [Hper Hord]].
rewrite /ms_bitness_vector_programmed_layer.
split.
- rewrite /ms_per_bit_programmed.
  by move=> i Hi; exact (Hper i Hi).
rewrite /ms_ordered_challenge_vector_matches.
have [Hlen_bits Hlen_glob] := Hshape.
by split=> //; split.
qed.

lemma ms3a_public_bitness_vector_programmed_of_game_execution
  (x : ms_public_input) :
  ms_bitness_vector_programmed_layer
    (ms3a_public_stmt_digest x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x).
proof.
exact (ms3a_public_bitness_vector_programmed_of_public_bitness_execution x
  (A_ms3a_public_bitness_execution x)).
qed.