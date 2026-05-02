require import AllCore List.
require import QssmTypes BitnessOne BitnessVector.
require import SourceTypes SourceModel.

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

(* Phase-1 constructors: wire the six `ms3a_public_*` spine fields into nominal real/sim
   payload records. Independent of abstract `d_ms3a_{real,sim}_payload_seed` until a
   later linking phase defines those laws from execution / games. *)

op ms3a_phase1_real_payload_from_public_input (x : ms_public_input) :
  ms3a_real_source_payload =
  {| ms3rp_stmt = ms3a_public_stmt_digest x;
     ms3rp_res = ms3a_public_result_bit x;
     ms3rp_bits = ms3a_public_bits x;
     ms3rp_bitness_global_challenges = ms3a_public_bitness_globals x;
     ms3rp_comparison_global_challenge = ms3a_public_comparison_global x;
     ms3rp_transcript_digest = ms3a_public_transcript_digest x |}.

op ms3a_phase1_sim_payload_from_public_input (x : ms_public_input) :
  ms3a_sim_source_payload =
  {| ms3sp_stmt = ms3a_public_stmt_digest x;
     ms3sp_res = ms3a_public_result_bit x;
     ms3sp_bits = ms3a_public_bits x;
     ms3sp_bitness_global_challenges = ms3a_public_bitness_globals x;
     ms3sp_comparison_global_challenge = ms3a_public_comparison_global x;
     ms3sp_transcript_digest = ms3a_public_transcript_digest x |}.

lemma L_ms3a_phase1_payload_pair_public_fields_match (x : ms_public_input) :
  ms3a_payload_pair_public_fields_match
    (ms3a_phase1_real_payload_from_public_input x)
    (ms3a_phase1_sim_payload_from_public_input x).
proof.
rewrite /ms3a_payload_pair_public_fields_match
  /ms3a_phase1_real_payload_from_public_input /ms3a_phase1_sim_payload_from_public_input.
by [].
qed.

(* `from_seed` stays the identity on nominal seeds: redefining it to ignore `sigma` and
   return only `ms3a_phase1_*_from_public_input x` would make every `dmap` pushforward
   through `from_seed` collapse to a point mass, contradicting abstract `d_ms3a_*_payload_seed`
   coupling. Linkage is therefore conditional on `sigma` agreeing with the Phase-1 spine. *)

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

lemma ms3a_real_payload_from_seed_eq_phase1_of_eq (x : ms_public_input) (sigma : ms3a_real_payload_seed) :
  sigma = ms3a_phase1_real_payload_from_public_input x =>
  ms3a_real_payload_from_seed x sigma = ms3a_phase1_real_payload_from_public_input x.
proof. by move=> ->; rewrite ms3a_real_payload_from_seed_def. qed.

lemma ms3a_sim_payload_from_seed_eq_phase1_of_eq
  (x : ms_public_input) (s : seed) (sigma : ms3a_sim_payload_seed) :
  sigma = ms3a_phase1_sim_payload_from_public_input x =>
  ms3a_sim_payload_from_seed x s sigma = ms3a_phase1_sim_payload_from_public_input x.
proof. by move=> ->; rewrite ms3a_sim_payload_from_seed_def. qed.

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

(* Bitness-global challenge list after `from_seed` agrees with seed-record fields. *)
lemma ms3a_payload_pair_bitness_global_challenges_eq_from_seed_of_seed_eq
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr.`ms3rp_bitness_global_challenges = ss.`ms3sp_bitness_global_challenges =>
  (ms3a_real_payload_from_seed x sr).`ms3rp_bitness_global_challenges =
    (ms3a_sim_payload_from_seed x s ss).`ms3sp_bitness_global_challenges.
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
