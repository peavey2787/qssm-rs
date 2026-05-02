require import AllCore List.
require import QssmTypes BitnessOne BitnessVector TranscriptObservable.

(* Structured source sampled before final observable pushforward. *)
type ms3a_bitness_layer_source = {
  ms3s_stmt : digest;
  ms3s_result : bool;
  ms3s_bits : ms_single_bit_or_transcript list;
  ms3s_bitness_global_challenges : digest list;
  ms3s_comparison_global_challenge : digest;
  ms3s_transcript_digest : digest;
}.

(* Constructor payloads: exactly the arguments to `ms3a_make_*_source`. *)
type ms3a_real_source_payload = {
  ms3rp_stmt : digest;
  ms3rp_res : bool;
  ms3rp_bits : ms_single_bit_or_transcript list;
  ms3rp_bitness_global_challenges : digest list;
  ms3rp_comparison_global_challenge : digest;
  ms3rp_transcript_digest : digest;
}.

type ms3a_sim_source_payload = {
  ms3sp_stmt : digest;
  ms3sp_res : bool;
  ms3sp_bits : ms_single_bit_or_transcript list;
  ms3sp_bitness_global_challenges : digest list;
  ms3sp_comparison_global_challenge : digest;
  ms3sp_transcript_digest : digest;
}.

(* Seeds for MS-3a payload laws: structurally the same records as constructor payloads
   (`ms3a_{real,sim}_source_payload`). Sampling laws `d_ms3a_{real,sim}_payload_seed` remain
   abstract; `ms3a_{real,sim}_payload_from_seed` is the identity (see `SourceConstructors.ec`)
   so execution/games can refine `d_ms3a_*_payload_seed` without changing the payload field
   surface. Public-input spine projections mirroring those six fields live in
   `ms/SourceModel.ec` (`ms3a_public_*`). Paired-public alignment: four `A_ms3a_seed_pair_*_source_shared` axioms on
   joint seed support feed four proved `A_ms3a_seed_pair_*_on_support` lemmas for
   `from_seed` payloads, which feed proved lemma `A_ms3a_seed_pair_public_fields_on_support`
   (`SourcePublicFieldObligations.ec` / `SourceConstructors.ec`; re-exported via
   `SourceObligations.ec`). Programmed-on-seed-support for each
   side is lemma `A_ms3a_{real,sim}_seed_programmed_on_support` from two field axioms
   (`*_bits_programmed_on_support`, `*_bitness_globals_programmed_on_support`) matching
   `ms_bitness_vector_programmed_layer` (`BitnessVector.ec`). *)
type ms3a_real_payload_seed = ms3a_real_source_payload.
type ms3a_sim_payload_seed = ms3a_sim_source_payload.

pred ms3a_source_wf (src : ms3a_bitness_layer_source) =
  ms_bitness_vector_programmed_layer src.`ms3s_stmt src.`ms3s_bits
    src.`ms3s_bitness_global_challenges.

pred ms3a_source_matches_v2_observable
  (src : ms3a_bitness_layer_source) (obs : ms_v2_transcript_observable) =
  obs.`msv2_statement_digest = src.`ms3s_stmt /\
  obs.`msv2_result_bit = src.`ms3s_result /\
  obs.`msv2_bitness_global_challenges = src.`ms3s_bitness_global_challenges /\
  obs.`msv2_comparison_global_challenge = src.`ms3s_comparison_global_challenge /\
  obs.`msv2_transcript_digest = src.`ms3s_transcript_digest.

pred ms3a_real_sim_sources_match_public_fields
  (real_src sim_src : ms3a_bitness_layer_source) =
  real_src.`ms3s_stmt = sim_src.`ms3s_stmt /\
  real_src.`ms3s_result = sim_src.`ms3s_result /\
  real_src.`ms3s_comparison_global_challenge = sim_src.`ms3s_comparison_global_challenge /\
  real_src.`ms3s_bitness_global_challenges = sim_src.`ms3s_bitness_global_challenges.

pred ms3a_sources_have_programmed_bitness_layer
  (real_src sim_src : ms3a_bitness_layer_source) =
  ms_bitness_vector_programmed_layer
    real_src.`ms3s_stmt real_src.`ms3s_bits real_src.`ms3s_bitness_global_challenges /\
  ms_bitness_vector_programmed_layer
    sim_src.`ms3s_stmt sim_src.`ms3s_bits sim_src.`ms3s_bitness_global_challenges.

(* Public-field conjuncts: four `*_source_shared` axioms on joint seed support; four
   `*_on_support` lemmata for `from_seed` payloads (`SourceObligations` /
   `SourceConstructors`). *)
pred ms3a_payload_pair_public_fields_match
  (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload) =
  pr.`ms3rp_stmt = ps.`ms3sp_stmt /\
  pr.`ms3rp_res = ps.`ms3sp_res /\
  pr.`ms3rp_comparison_global_challenge = ps.`ms3sp_comparison_global_challenge /\
  pr.`ms3rp_bitness_global_challenges = ps.`ms3sp_bitness_global_challenges.
