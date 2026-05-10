require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceTypes SourceModel SourceConstructors.

(* MS-3a minimal concrete execution/game-link boundary.

   This theory fixes the first concrete boundary objects needed by the future
   execution theorem, without claiming that ROM/FS programmed-layer semantics
   are already proved.

   The current source sampler shape is intentionally minimal: a point mass at
   the canonical public spine record. This gives downstream theories a concrete
   source-level distribution object and a concrete `dmap`-implemented execution
   seed law, while keeping the remaining proof debt local to theorem lemmas
   rather than new axioms. *)

op ms3a_game_public_bitness_source (x : ms_public_input) : ms3a_bitness_layer_source =
  ms3a_make_real_source
    (ms3a_public_stmt_digest x)
    (ms3a_public_result_bit x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x)
    (ms3a_public_comparison_global x)
    (ms3a_public_transcript_digest x).

op d_ms3a_real_execution_bitness_source
  (x : ms_public_input) : ms3a_bitness_layer_source distr =
  dunit (ms3a_game_public_bitness_source x).

op d_ms3a_real_execution_public_seed
  (x : ms_public_input) : ms3a_real_payload_seed distr =
  dmap (d_ms3a_real_execution_bitness_source x) ms3a_real_payload_seed_of_bitness_layer.

lemma ms3a_game_public_bitness_source_projects_public_spine
  (x : ms_public_input) :
  (ms3a_game_public_bitness_source x).`ms3s_stmt = ms3a_public_stmt_digest x /\
  (ms3a_game_public_bitness_source x).`ms3s_bits = ms3a_public_bits x /\
  (ms3a_game_public_bitness_source x).`ms3s_bitness_global_challenges =
    ms3a_public_bitness_globals x /\
  (ms3a_game_public_bitness_source x).`ms3s_transcript_digest =
    ms3a_public_transcript_digest x.
proof.
rewrite /ms3a_game_public_bitness_source /ms3a_make_real_source /=.
by split=> //; split=> //.
qed.

lemma ms3a_game_public_bitness_source_transcript_shape_iff
  (x : ms_public_input) :
  ms3a_public_transcript_shape_ok x <=>
  (ms3a_game_public_bitness_source x).`ms3s_transcript_digest =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).
proof.
rewrite (ms3a_public_transcript_shape_ok_iff_digest_by_construction x).
by rewrite /ms3a_game_public_bitness_source /ms3a_make_real_source.
qed.

lemma ms3a_game_public_bitness_source_transcript_digest_canonical
  (x : ms_public_input) :
  (ms3a_game_public_bitness_source x).`ms3s_transcript_digest =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).
proof.
rewrite /ms3a_game_public_bitness_source /ms3a_make_real_source.
exact (ms3a_public_transcript_digest_by_construction x).
qed.

lemma ms3a_game_public_bitness_source_transcript_shape
  (x : ms_public_input) :
  ms3a_public_transcript_shape_ok x.
proof.
exact (ms3a_public_transcript_shape_ok_holds x).
qed.

lemma ms3a_real_execution_public_seed_support_inv
  (x : ms_public_input) (sigma : ms3a_real_payload_seed) :
  sigma \in d_ms3a_real_execution_public_seed x =>
  exists (src : ms3a_bitness_layer_source),
    src \in d_ms3a_real_execution_bitness_source x /\
    sigma = ms3a_real_payload_seed_of_bitness_layer src.
proof.
move=> Hsig.
rewrite /d_ms3a_real_execution_public_seed in Hsig.
case/supp_dmap: Hsig=> src [Hsrc Heq].
by exists src.
qed.

lemma ms3a_real_execution_bitness_source_public_fields_on_support
  (x : ms_public_input) (src : ms3a_bitness_layer_source) :
  src \in d_ms3a_real_execution_bitness_source x =>
  src.`ms3s_stmt = ms3a_public_stmt_digest x /\
  src.`ms3s_bits = ms3a_public_bits x /\
  src.`ms3s_bitness_global_challenges = ms3a_public_bitness_globals x.
proof.
move=> Hsrc.
rewrite /d_ms3a_real_execution_bitness_source in Hsrc.
move: Hsrc; rewrite supp_dunit => ->.
have [Hstmt [Hbits [Hglob _]]] := ms3a_game_public_bitness_source_projects_public_spine x.
by split=> //; split.
qed.

lemma ms3a_game_real_execution_seed_public_fields
  (x : ms_public_input) (sigma : ms3a_real_payload_seed) :
  sigma \in d_ms3a_real_execution_public_seed x =>
  sigma.`ms3rp_stmt = ms3a_public_stmt_digest x /\
  sigma.`ms3rp_bits = ms3a_public_bits x /\
  sigma.`ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x.
proof.
move=> Hsig.
have [src [Hsrc ->]] := ms3a_real_execution_public_seed_support_inv x sigma Hsig.
have [Hstmt [Hbits Hglob]] :=
  ms3a_real_execution_bitness_source_public_fields_on_support x src Hsrc.
split.
- move: Hstmt.
  by rewrite /ms3a_real_payload_seed_of_bitness_layer.
split.
- move: Hbits.
  by rewrite /ms3a_real_payload_seed_of_bitness_layer.
move: Hglob.
by rewrite /ms3a_real_payload_seed_of_bitness_layer.
qed.

(* The structural boundary lemmas above are now definitional facts of the
   concrete `dunit`/`dmap` boundary:
   - `ms3a_game_public_bitness_source_projects_public_spine`
   - `ms3a_real_execution_public_seed_support_inv`
   - `ms3a_real_execution_bitness_source_public_fields_on_support`
   - `ms3a_game_real_execution_seed_public_fields`

   Semantic public-bitness closure now lives in
   `SourceRealExecutionSeed.ec`, where the real-seed bridge axiom is available
   to connect this concrete execution source back to abstract spine support. *)