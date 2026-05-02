require import AllCore List.
require import QssmTypes BitnessOne BitnessVector.
require import SourceTypes.

op ms3a_make_real_source
  (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = rbit;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

op ms3a_make_sim_source
  (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = rbit;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

op ms3a_bitness_layer_source_of_real_payload (p : ms3a_real_source_payload) :
  ms3a_bitness_layer_source =
  ms3a_make_real_source p.`ms3rp_stmt p.`ms3rp_res p.`ms3rp_bits
    p.`ms3rp_bitness_global_challenges p.`ms3rp_comparison_global_challenge
    p.`ms3rp_transcript_digest.

op ms3a_bitness_layer_source_of_sim_payload (p : ms3a_sim_source_payload) :
  ms3a_bitness_layer_source =
  ms3a_make_sim_source p.`ms3sp_stmt p.`ms3sp_res p.`ms3sp_bits
    p.`ms3sp_bitness_global_challenges p.`ms3sp_comparison_global_challenge
    p.`ms3sp_transcript_digest.

(* Seed → payload: identity on the shared record type (`SourceTypes.ec`). `x` / `s` are
   retained for API stability when linking to keyed samplers from execution. *)
op ms3a_real_payload_from_seed (x : ms_public_input) (sigma : ms3a_real_payload_seed) :
  ms3a_real_source_payload =
  sigma.

op ms3a_sim_payload_from_seed (x : ms_public_input) (s : seed) (sigma : ms3a_sim_payload_seed) :
  ms3a_sim_source_payload =
  sigma.

lemma ms3a_real_payload_from_seed_def (x : ms_public_input) (sigma : ms3a_real_payload_seed) :
  ms3a_real_payload_from_seed x sigma = sigma.
proof. by []. qed.

lemma ms3a_sim_payload_from_seed_def (x : ms_public_input) (s : seed) (sigma : ms3a_sim_payload_seed) :
  ms3a_sim_payload_from_seed x s sigma = sigma.
proof. by []. qed.

(* Statement digest after `from_seed` agrees with seed-record fields (identity packaging). *)
lemma ms3a_payload_pair_stmt_eq_from_seed_of_seed_stmt_eq
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr.`ms3rp_stmt = ss.`ms3sp_stmt =>
  (ms3a_real_payload_from_seed x sr).`ms3rp_stmt =
    (ms3a_sim_payload_from_seed x s ss).`ms3sp_stmt.
proof. by rewrite ms3a_real_payload_from_seed_def ms3a_sim_payload_from_seed_def. qed.

(* Result bit after `from_seed` agrees with seed-record fields (identity packaging). *)
lemma ms3a_payload_pair_res_eq_from_seed_of_seed_res_eq
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr.`ms3rp_res = ss.`ms3sp_res =>
  (ms3a_real_payload_from_seed x sr).`ms3rp_res =
    (ms3a_sim_payload_from_seed x s ss).`ms3sp_res.
proof. by rewrite ms3a_real_payload_from_seed_def ms3a_sim_payload_from_seed_def. qed.

(* Comparison-global digest after `from_seed` agrees with seed-record fields. *)
lemma ms3a_payload_pair_comparison_global_challenge_eq_from_seed_of_seed_eq
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr.`ms3rp_comparison_global_challenge = ss.`ms3sp_comparison_global_challenge =>
  (ms3a_real_payload_from_seed x sr).`ms3rp_comparison_global_challenge =
    (ms3a_sim_payload_from_seed x s ss).`ms3sp_comparison_global_challenge.
proof. by rewrite ms3a_real_payload_from_seed_def ms3a_sim_payload_from_seed_def. qed.

(* Payload-level: same programmed-vector obligation as `ms3a_source_wf` on the
   constructor image of each payload (support axioms mention payload laws only,
   not folded bitness source distributions). *)
pred ms3a_real_payload_programmed_layer (p : ms3a_real_source_payload) =
  ms3a_source_wf (ms3a_bitness_layer_source_of_real_payload p).

lemma ms3a_real_payload_programmed_layer_as_bitness_vector
  (p : ms3a_real_source_payload) :
  ms3a_real_payload_programmed_layer p <=>
  ms_bitness_vector_programmed_layer p.`ms3rp_stmt p.`ms3rp_bits
    p.`ms3rp_bitness_global_challenges.
proof.
rewrite /ms3a_real_payload_programmed_layer /ms3a_bitness_layer_source_of_real_payload
  /ms3a_make_real_source /ms3a_source_wf.
by [].
qed.

pred ms3a_sim_payload_programmed_layer (p : ms3a_sim_source_payload) =
  ms3a_source_wf (ms3a_bitness_layer_source_of_sim_payload p).

lemma ms3a_sim_payload_programmed_layer_as_bitness_vector
  (p : ms3a_sim_source_payload) :
  ms3a_sim_payload_programmed_layer p <=>
  ms_bitness_vector_programmed_layer p.`ms3sp_stmt p.`ms3sp_bits
    p.`ms3sp_bitness_global_challenges.
proof.
rewrite /ms3a_sim_payload_programmed_layer /ms3a_bitness_layer_source_of_sim_payload
  /ms3a_make_sim_source /ms3a_source_wf.
by [].
qed.
