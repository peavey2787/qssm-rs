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

(* Planned theorem targets for the next phase:
   - `ms3a_public_bits_shape_of_execution`
   - `ms3a_public_bitness_globals_ordered_of_execution`
   - `ms3a_public_bits_per_bit_programmed_of_execution`
   - `ms3a_public_bitness_execution_of_game_execution`

   Intended use:
   instantiate these constructors on the concrete execution/game source, then
   add a single equality bridge back to the abstract `ms3a_public_bits x` /
   `ms3a_public_bitness_globals x` projections rather than redefining
   `SourceModel.ec` from below. *)