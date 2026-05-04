require import AllCore List.
require import Domains QssmTypes Algebra FS SchnorrBranch BitnessOne BitnessVector TranscriptObservable.

(* Concrete MS public carrier used by the MS-3a public spine and the game view.
   Each public bit slot stores just enough material to build a programmed
   `ms_single_bit_or_transcript` constructively at its index. *)
type ms_public_bit_input = {
  mspbi_branch0 : schnorr_single_bit_obsv;
  mspbi_branch1 : schnorr_single_bit_obsv;
  mspbi_challenge_zero : scalar;
}.

type ms_public_input = {
  mspi_stmt_digest : digest;
  mspi_result_bit : bool;
  mspi_bits : int -> ms_public_bit_input;
  mspi_comparison_slice : ms_comparison_slice;
  mspi_comparison_global : digest;
  mspi_transcript_digest : digest;
}.

op ms_public_bit_payload (x : ms_public_input) (i : int) : ms_public_bit_input =
  x.`mspi_bits i.

op ms_public_comparison_slice (x : ms_public_input) : ms_comparison_slice =
  x.`mspi_comparison_slice.

op ms_public_comparison_true_clause_index_raw (x : ms_public_input) : int =
  (ms_public_comparison_slice x).`mscs_true_clause_ix.

op ms_public_comparison_true_clause_index (x : ms_public_input) : int =
  if 0 <= ms_public_comparison_true_clause_index_raw x
  then ms_public_comparison_true_clause_index_raw x
  else 0.

op ms_public_comparison_true_opening (x : ms_public_input) : ms_comparison_opening =
  (ms_public_comparison_slice x).`mscs_true_opening.

op ms_public_comparison_false_entries (x : ms_public_input) : ms_comparison_false_entry list =
  (ms_public_comparison_slice x).`mscs_false_entries.

op ms_public_comparison_false_openings (x : ms_public_input) : ms_comparison_opening list =
  map (fun (entry : ms_comparison_false_entry) => entry.`mscfe_opening)
    (ms_public_comparison_false_entries x).

op ms_public_comparison_false_indices (x : ms_public_input) : int list =
  map (fun (entry : ms_comparison_false_entry) => entry.`mscfe_clause_ix)
    (ms_public_comparison_false_entries x).

op ms_public_bit_pub0 (x : ms_public_input) (i : int) : sch_point =
  (ms_public_bit_payload x i).`mspbi_branch0.`1.

op ms_public_bit_pub1 (x : ms_public_input) (i : int) : sch_point =
  (ms_public_bit_payload x i).`mspbi_branch1.`1.

op ms_public_bit_challenge_zero (x : ms_public_input) (i : int) : scalar =
  (ms_public_bit_payload x i).`mspbi_challenge_zero.

op ms_public_bit_global_challenge (x : ms_public_input) (i : int) : scalar =
  ms_bitness_fs_scalar x.`mspi_stmt_digest i
    (ms_single_bit_branch_digest (ms_public_bit_pub0 x i))
    (ms_single_bit_branch_digest (ms_public_bit_pub1 x i)).

op ms_public_bit_challenge_one (x : ms_public_input) (i : int) : scalar =
  sch_s_sub (ms_public_bit_global_challenge x i) (ms_public_bit_challenge_zero x i).

op ms_public_bit_transcript (x : ms_public_input) (i : int) : ms_single_bit_or_transcript =
  ms_pack_single_bit_or x.`mspi_stmt_digest
    (ms_public_bit_pub0 x i)
    (ms_public_bit_pub1 x i)
    (ms_public_bit_payload x i).`mspbi_branch0
    (ms_public_bit_payload x i).`mspbi_branch1
    (ms_public_bit_challenge_zero x i)
    (ms_public_bit_challenge_one x i)
    (ms_public_bit_global_challenge x i).

op ms_public_bit_global_digest (x : ms_public_input) (i : int) : digest =
  ms_bitness_challenge_scalar_digest (ms_public_bit_global_challenge x i).

op ms_public_bitness_global_digests (x : ms_public_input) : digest list =
  [ ms_public_bit_global_digest x 0;  ms_public_bit_global_digest x 1;
    ms_public_bit_global_digest x 2;  ms_public_bit_global_digest x 3;
    ms_public_bit_global_digest x 4;  ms_public_bit_global_digest x 5;
    ms_public_bit_global_digest x 6;  ms_public_bit_global_digest x 7;
    ms_public_bit_global_digest x 8;  ms_public_bit_global_digest x 9;
    ms_public_bit_global_digest x 10; ms_public_bit_global_digest x 11;
    ms_public_bit_global_digest x 12; ms_public_bit_global_digest x 13;
    ms_public_bit_global_digest x 14; ms_public_bit_global_digest x 15;
    ms_public_bit_global_digest x 16; ms_public_bit_global_digest x 17;
    ms_public_bit_global_digest x 18; ms_public_bit_global_digest x 19;
    ms_public_bit_global_digest x 20; ms_public_bit_global_digest x 21;
    ms_public_bit_global_digest x 22; ms_public_bit_global_digest x 23;
    ms_public_bit_global_digest x 24; ms_public_bit_global_digest x 25;
    ms_public_bit_global_digest x 26; ms_public_bit_global_digest x 27;
    ms_public_bit_global_digest x 28; ms_public_bit_global_digest x 29;
    ms_public_bit_global_digest x 30; ms_public_bit_global_digest x 31;
    ms_public_bit_global_digest x 32; ms_public_bit_global_digest x 33;
    ms_public_bit_global_digest x 34; ms_public_bit_global_digest x 35;
    ms_public_bit_global_digest x 36; ms_public_bit_global_digest x 37;
    ms_public_bit_global_digest x 38; ms_public_bit_global_digest x 39;
    ms_public_bit_global_digest x 40; ms_public_bit_global_digest x 41;
    ms_public_bit_global_digest x 42; ms_public_bit_global_digest x 43;
    ms_public_bit_global_digest x 44; ms_public_bit_global_digest x 45;
    ms_public_bit_global_digest x 46; ms_public_bit_global_digest x 47;
    ms_public_bit_global_digest x 48; ms_public_bit_global_digest x 49;
    ms_public_bit_global_digest x 50; ms_public_bit_global_digest x 51;
    ms_public_bit_global_digest x 52; ms_public_bit_global_digest x 53;
    ms_public_bit_global_digest x 54; ms_public_bit_global_digest x 55;
    ms_public_bit_global_digest x 56; ms_public_bit_global_digest x 57;
    ms_public_bit_global_digest x 58; ms_public_bit_global_digest x 59;
    ms_public_bit_global_digest x 60; ms_public_bit_global_digest x 61;
    ms_public_bit_global_digest x 62; ms_public_bit_global_digest x 63 ].

op ms_public_transcript_digest_canonical (x : ms_public_input) : digest =
  hash_domain LABEL_MS_V2_PROOF
    (x.`mspi_stmt_digest ::
     ms_result_bit_digest x.`mspi_result_bit ::
     x.`mspi_comparison_global ::
     ms_public_bitness_global_digests x).

op ms_make_public_input
  (stmt : digest) (rbit : bool)
  (bits : int -> ms_public_bit_input)
  (comparison_slice : ms_comparison_slice)
  (comparison_global : digest) : ms_public_input =
  let x0 = {| mspi_stmt_digest = stmt;
              mspi_result_bit = rbit;
              mspi_bits = bits;
              mspi_comparison_slice = comparison_slice;
              mspi_comparison_global = comparison_global;
              mspi_transcript_digest = witness |} in
  {| mspi_stmt_digest = stmt;
     mspi_result_bit = rbit;
     mspi_bits = bits;
     mspi_comparison_slice = comparison_slice;
     mspi_comparison_global = comparison_global;
     mspi_transcript_digest = ms_public_transcript_digest_canonical x0 |}.

lemma ms_make_public_input_transcript_digest_canonical
  (stmt : digest) (rbit : bool)
  (bits : int -> ms_public_bit_input)
  (comparison_slice : ms_comparison_slice)
  (comparison_global : digest) :
  (ms_make_public_input stmt rbit bits comparison_slice comparison_global).`mspi_transcript_digest =
  ms_public_transcript_digest_canonical
    (ms_make_public_input stmt rbit bits comparison_slice comparison_global).
proof.
rewrite /ms_make_public_input /ms_public_transcript_digest_canonical /=.
by [].
qed.

lemma ms_public_bit_transcript_programmed (x : ms_public_input) (i : int) :
  (ms_public_bit_transcript x i).`msbt_stmt = x.`mspi_stmt_digest /\
  ms_single_bit_programmed_bitness_transcript
    x.`mspi_stmt_digest i
    (ms_public_bit_transcript x i).`msbt_pub0
    (ms_public_bit_transcript x i).`msbt_pub1
    (ms_public_bit_transcript x i).`msbt_branch0
    (ms_public_bit_transcript x i).`msbt_branch1
    (ms_public_bit_transcript x i).`msbt_challenge_zero
    (ms_public_bit_transcript x i).`msbt_challenge_one
    (ms_public_bit_transcript x i).`msbt_global_challenge.
proof.
split.
- rewrite /ms_public_bit_transcript /ms_public_bit_pub0 /ms_public_bit_pub1.
  rewrite /ms_public_bit_payload /ms_public_bit_challenge_zero.
  rewrite /ms_public_bit_challenge_one /ms_public_bit_global_challenge.
  by rewrite /ms_pack_single_bit_or /=.
- rewrite /ms_public_bit_transcript /ms_public_bit_pub0 /ms_public_bit_pub1.
  rewrite /ms_pack_single_bit_or /ms_single_bit_programmed_bitness_transcript /=.
  have Hsplit :
    ms_challenges_split
      (ms_public_bit_challenge_zero x i)
      (ms_public_bit_challenge_one x i)
      (ms_public_bit_global_challenge x i).
  - rewrite /ms_challenges_split.
    by rewrite sch_s_addC sch_s_sub_def.
  have Hfs :
    ms_bitness_fs_programmed x.`mspi_stmt_digest i
      (ms_single_bit_branch_digest (ms_public_bit_pub0 x i))
      (ms_single_bit_branch_digest (ms_public_bit_pub1 x i))
      (ms_public_bit_global_challenge x i)
    by rewrite /ms_bitness_fs_programmed.
  by smt.
qed.

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

pred ms3a_payload_pair_public_fields_match
  (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload) =
  pr.`ms3rp_stmt = ps.`ms3sp_stmt /\
  pr.`ms3rp_res = ps.`ms3sp_res /\
  pr.`ms3rp_comparison_global_challenge = ps.`ms3sp_comparison_global_challenge /\
  pr.`ms3rp_bitness_global_challenges = ps.`ms3sp_bitness_global_challenges.

(* MS sub-game stages inside the G0→G1 hop (QSSM-level public input + seed). *)
type ms_game_stage = [
  | MSGameStageReal
  | MSGameStageAfterBinding
  | MSGameStageAfterRom
  | MSGameStageAfterBitness
  | MSGameStageAfterComparison
  | MSGameStageSim
].

(* Structured MS slice of a QSSM game view (LE slot optional for QSSM wiring). *)
type ms_game_view_record = {
  msgv_qssm_pub : qssm_public_input;
  msgv_seed : seed;
  msgv_ms_pub : ms_public_input;
  msgv_ms_obs : ms_v2_transcript_observable;
  msgv_stage : ms_game_stage;
  msgv_le_placeholder : le_transcript_observable option;
}.

(* QSSM game views: MS-structured hops, or G2 full-sim shell (LE-heavy) for now. *)
type qssm_g1_le_real_record = {
  qg1_pub : qssm_public_input;
  qg1_ms_pub : ms_public_input;
  qg1_seed : seed;
}.

type qssm_g2_shell_record = {
  qg2_pub : qssm_public_input;
  qg2_seed : seed;
}.

type game_view = [
  | GV_ms of ms_game_view_record
  | GV_g1_le_real of qssm_g1_le_real_record
  | GV_g2_full_sim of qssm_g2_shell_record
].