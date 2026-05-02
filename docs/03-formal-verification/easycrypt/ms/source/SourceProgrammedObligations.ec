require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.

(* `ms3a_ax_*` predicates and real/sim seed programmed-layer obligations. *)

pred ms3a_ax_real_wf (x : ms_public_input) =
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.

pred ms3a_ax_sim_wf (x : ms_public_input) (s : seed) =
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.

pred ms3a_ax_public_fields (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields real_src sim_src.

pred ms3a_ax_prog_layer (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer real_src sim_src.

pred ms3a_ax_bitness_exact (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.

axiom A_ms3a_real_seed_bits_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms_per_bit_programmed sigma.`ms3rp_stmt sigma.`ms3rp_bits.

axiom A_ms3a_real_seed_bitness_globals_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms_ordered_challenge_vector_matches sigma.`ms3rp_bits
      sigma.`ms3rp_bitness_global_challenges.

lemma A_ms3a_real_seed_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms3a_real_payload_programmed_layer (ms3a_real_payload_from_seed x sigma).
proof.
move=> sigma Hsig.
rewrite ms3a_real_payload_from_seed_def /ms3a_real_payload_programmed_layer
  /ms3a_bitness_layer_source_of_real_payload /ms3a_make_real_source /ms3a_source_wf
  /ms_bitness_vector_programmed_layer.
split.
- exact (A_ms3a_real_seed_bits_programmed_on_support x sigma Hsig).
- exact (A_ms3a_real_seed_bitness_globals_programmed_on_support x sigma Hsig).
qed.

axiom A_ms3a_sim_seed_bits_programmed_on_support (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms_per_bit_programmed sigma.`ms3sp_stmt sigma.`ms3sp_bits.

axiom A_ms3a_sim_seed_bitness_globals_programmed_on_support
  (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms_ordered_challenge_vector_matches sigma.`ms3sp_bits
      sigma.`ms3sp_bitness_global_challenges.

lemma A_ms3a_sim_seed_programmed_on_support (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms3a_sim_payload_programmed_layer (ms3a_sim_payload_from_seed x s sigma).
proof.
move=> sigma Hsig.
rewrite ms3a_sim_payload_from_seed_def /ms3a_sim_payload_programmed_layer
  /ms3a_bitness_layer_source_of_sim_payload /ms3a_make_sim_source /ms3a_source_wf
  /ms_bitness_vector_programmed_layer.
split.
- exact (A_ms3a_sim_seed_bits_programmed_on_support x s sigma Hsig).
- exact (A_ms3a_sim_seed_bitness_globals_programmed_on_support x s sigma Hsig).
qed.
