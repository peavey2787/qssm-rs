require import AllCore List.
require import QssmTypes BitnessOne BitnessVector.
require import SourceTypes.

(* MS-3a concrete public-bitness constructor surface.

   This theory fixes the list-level objects that the future public-bitness
   execution theorem should talk about directly. The constructors live on the
   concrete `ms3a_bitness_layer_source` record rather than on the abstract
   `SourceModel.ec` projections, so the next phase can instantiate them on the
   concrete game/source object without changing `SourceModel.ec` yet. *)

op ms3a_public_bits_of_execution
  (src : ms3a_bitness_layer_source) : ms_single_bit_or_transcript list =
  src.`ms3s_bits.

op ms3a_public_bitness_global_digest_of_execution
  (t : ms_single_bit_or_transcript) : digest =
  ms_bitness_challenge_scalar_digest t.`msbt_global_challenge.

op ms3a_public_bitness_globals_of_execution
  (src : ms3a_bitness_layer_source) : digest list =
  map ms3a_public_bitness_global_digest_of_execution
    (ms3a_public_bits_of_execution src).

lemma ms3a_public_bitness_globals_of_executionE
  (src : ms3a_bitness_layer_source) :
  ms3a_public_bitness_globals_of_execution src =
  map ms3a_public_bitness_global_digest_of_execution
    (ms3a_public_bits_of_execution src).
proof.
by rewrite /ms3a_public_bitness_globals_of_execution.
qed.

lemma ms3a_public_bits_shape_of_execution
  (src : ms3a_bitness_layer_source) :
  ms_bitness_vector_length_ok (ms3a_public_bits_of_execution src) =>
  ms_bitness_vector_length_ok (ms3a_public_bits_of_execution src) /\
  ms_bitness_global_challenge_vector_length_ok
    (ms3a_public_bitness_globals_of_execution src).
proof.
move=> Hbits.
split=> //.
rewrite /ms_bitness_global_challenge_vector_length_ok
  /ms3a_public_bitness_globals_of_execution size_map.
by move: Hbits; rewrite /ms_bitness_vector_length_ok.
qed.

lemma ms3a_public_bitness_globals_ordered_of_execution
  (src : ms3a_bitness_layer_source) :
  ms_bitness_vector_length_ok (ms3a_public_bits_of_execution src) =>
  ms_ordered_challenge_vector_matches
    (ms3a_public_bits_of_execution src)
    (ms3a_public_bitness_globals_of_execution src).
proof.
move=> Hbits.
rewrite /ms_ordered_challenge_vector_matches.
have [Hbits_ok Hglob_ok] := ms3a_public_bits_shape_of_execution src Hbits.
split=> //; split=> //.
move=> i Hi.
have Hsize : size (ms3a_public_bits_of_execution src) = V2_BIT_COUNT.
  by move: Hbits; rewrite /ms_bitness_vector_length_ok.
have Hrange : 0 <= i < size (ms3a_public_bits_of_execution src).
  have [Hlo Hhi] := Hi.
  split=> //.
  by rewrite Hsize.
rewrite /ms3a_public_bitness_globals_of_execution
  /ms3a_public_bitness_global_digest_of_execution.
by rewrite (nth_map witness witness
  ms3a_public_bitness_global_digest_of_execution i
  (ms3a_public_bits_of_execution src)) //.
qed.

lemma ms3a_public_bits_per_bit_programmed_of_execution
  (src : ms3a_bitness_layer_source) :
  ms3a_source_wf src =>
  ms_per_bit_programmed src.`ms3s_stmt (ms3a_public_bits_of_execution src).
proof.
move=> Hwf.
move: Hwf; rewrite /ms3a_source_wf /ms_bitness_vector_programmed_layer
  /ms3a_public_bits_of_execution.
by move=> [Hper _].
qed.

(* Planned theorem targets for the next phase:
   - `ms3a_public_bitness_execution_of_game_execution`

   Intended use:
   instantiate these constructors on the concrete execution/game source, then
   add a single equality bridge back to the abstract `ms3a_public_bits x` /
   `ms3a_public_bitness_globals x` projections rather than redefining
   `SourceModel.ec` from below.

   Current bridge status:
   the structural constructor lemmas above are proved, and the per-bit
  programmed lemma closes once `ms3a_source_wf` is available for the concrete
  source. That semantic closure is now proved higher in
  `SourceRealExecutionSeed.ec`, where the real-seed bridge axiom is available
  to place the concrete game source on abstract spine support. *)