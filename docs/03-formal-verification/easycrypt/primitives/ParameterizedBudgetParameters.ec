require import AllCore Int List Distr.
require import BudgetParameters.
import Ring.IntID StdOrder.IntOrder.

(* Parallel parameterized owner surface.
   The current instantiation aliases the live demo counts so the new lane stays
   proof-closed without changing any existing theorem names or owners. *)

op ms1_param_collision_count : int =
  BudgetParameters.ms_hash_binding_collision_slot_count.

op ms1_param_malformed_binding_count : int =
  BudgetParameters.ms_hash_binding_malformed_binding_slot_count.

op ms1_param_transcript_count : int =
  BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count.

op ms1_param_clean_count : int =
  BudgetParameters.ms_hash_binding_clean_slot_count.

op ms1_param_failure_count : int =
  ms1_param_collision_count +
  ms1_param_malformed_binding_count +
  ms1_param_transcript_count.

op ms1_param_total_count : int =
  ms1_param_clean_count + ms1_param_failure_count.

lemma ms1_param_failure_count_component_sum :
  ms1_param_failure_count =
  ms1_param_collision_count +
  ms1_param_malformed_binding_count +
  ms1_param_transcript_count.
proof. by rewrite /ms1_param_failure_count. qed.

lemma ms1_param_collision_count_nonneg :
  0 <= ms1_param_collision_count.
proof.
rewrite /ms1_param_collision_count.
exact BudgetParameters.ms_hash_binding_collision_slot_count_nonneg.
qed.

lemma ms1_param_malformed_binding_count_nonneg :
  0 <= ms1_param_malformed_binding_count.
proof.
rewrite /ms1_param_malformed_binding_count.
exact BudgetParameters.ms_hash_binding_malformed_binding_slot_count_nonneg.
qed.

lemma ms1_param_transcript_count_nonneg :
  0 <= ms1_param_transcript_count.
proof.
rewrite /ms1_param_transcript_count.
exact BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count_nonneg.
qed.

lemma ms1_param_clean_count_nonneg :
  0 <= ms1_param_clean_count.
proof.
rewrite /ms1_param_clean_count.
exact BudgetParameters.ms_hash_binding_clean_slot_count_nonneg.
qed.

lemma ms1_param_clean_count_pos :
  0 < ms1_param_clean_count.
proof.
rewrite /ms1_param_clean_count.
exact BudgetParameters.ms_hash_binding_clean_slot_count_pos.
qed.

lemma ms1_param_failure_count_nonneg :
  0 <= ms1_param_failure_count.
proof.
rewrite /ms1_param_failure_count.
by smt(ms1_param_collision_count_nonneg
       ms1_param_malformed_binding_count_nonneg
       ms1_param_transcript_count_nonneg).
qed.

lemma ms1_param_total_count_nonneg :
  0 <= ms1_param_total_count.
proof.
rewrite /ms1_param_total_count.
by smt(ms1_param_clean_count_nonneg ms1_param_failure_count_nonneg).
qed.

lemma ms1_param_total_count_pos :
  0 < ms1_param_total_count.
proof.
rewrite /ms1_param_total_count.
by smt(ms1_param_clean_count_pos ms1_param_failure_count_nonneg).
qed.

lemma ms1_param_failure_count_le_total_count :
  ms1_param_failure_count <= ms1_param_total_count.
proof.
rewrite /ms1_param_total_count.
by smt(ms1_param_clean_count_nonneg).
qed.

op epsilon_ms_hash_binding_parameterized : real =
  ms1_param_failure_count%r / ms1_param_total_count%r.

lemma epsilon_ms_hash_binding_parameterized_closed_form :
  epsilon_ms_hash_binding_parameterized =
  ms1_param_failure_count%r / ms1_param_total_count%r.
proof. by rewrite /epsilon_ms_hash_binding_parameterized. qed.

lemma epsilon_ms_hash_binding_parameterized_nonneg :
  0%r <= epsilon_ms_hash_binding_parameterized.
proof.
rewrite epsilon_ms_hash_binding_parameterized_closed_form.
by smt(ms1_param_failure_count_nonneg ms1_param_total_count_pos).
qed.

op ms2_param_global_digest_count : int =
  BudgetParameters.ms_rom_query_collision_slot_count.

op ms2_param_query_digest_count : int =
  BudgetParameters.ms_rom_programming_collision_slot_count.

op ms2_param_transcript_count : int =
  BudgetParameters.ms_rom_transcript_mismatch_slot_count.

op ms2_param_clean_count : int =
  BudgetParameters.ms_rom_clean_slot_count.

op ms2_param_failure_count : int =
  ms2_param_global_digest_count +
  ms2_param_query_digest_count +
  ms2_param_transcript_count.

op ms2_param_total_count : int =
  ms2_param_clean_count + ms2_param_failure_count.

lemma ms2_param_failure_count_component_sum :
  ms2_param_failure_count =
  ms2_param_global_digest_count +
  ms2_param_query_digest_count +
  ms2_param_transcript_count.
proof. by rewrite /ms2_param_failure_count. qed.

lemma ms2_param_global_digest_count_nonneg :
  0 <= ms2_param_global_digest_count.
proof.
rewrite /ms2_param_global_digest_count.
exact BudgetParameters.ms_rom_query_collision_slot_count_nonneg.
qed.

lemma ms2_param_query_digest_count_nonneg :
  0 <= ms2_param_query_digest_count.
proof.
rewrite /ms2_param_query_digest_count.
exact BudgetParameters.ms_rom_programming_collision_slot_count_nonneg.
qed.

lemma ms2_param_transcript_count_nonneg :
  0 <= ms2_param_transcript_count.
proof.
rewrite /ms2_param_transcript_count.
exact BudgetParameters.ms_rom_transcript_mismatch_slot_count_nonneg.
qed.

lemma ms2_param_clean_count_nonneg :
  0 <= ms2_param_clean_count.
proof.
rewrite /ms2_param_clean_count.
exact BudgetParameters.ms_rom_clean_slot_count_nonneg.
qed.

lemma ms2_param_clean_count_pos :
  0 < ms2_param_clean_count.
proof.
rewrite /ms2_param_clean_count.
exact BudgetParameters.ms_rom_clean_slot_count_pos.
qed.

lemma ms2_param_failure_count_nonneg :
  0 <= ms2_param_failure_count.
proof.
rewrite /ms2_param_failure_count.
by smt(ms2_param_global_digest_count_nonneg
       ms2_param_query_digest_count_nonneg
       ms2_param_transcript_count_nonneg).
qed.

lemma ms2_param_failure_count_pos :
  0 < ms2_param_failure_count.
proof.
rewrite /ms2_param_failure_count.
by smt(ms2_param_global_digest_count_nonneg
       ms2_param_query_digest_count_nonneg
       ms2_param_transcript_count_nonneg).
qed.

lemma ms2_param_total_count_nonneg :
  0 <= ms2_param_total_count.
proof.
rewrite /ms2_param_total_count.
by smt(ms2_param_clean_count_nonneg ms2_param_failure_count_nonneg).
qed.

lemma ms2_param_total_count_pos :
  0 < ms2_param_total_count.
proof.
rewrite /ms2_param_total_count.
by smt(ms2_param_clean_count_pos ms2_param_failure_count_nonneg).
qed.

lemma ms2_param_failure_count_le_total_count :
  ms2_param_failure_count <= ms2_param_total_count.
proof.
rewrite /ms2_param_total_count.
by smt(ms2_param_clean_count_nonneg).
qed.

lemma ms2_param_failure_count_lt_total_count :
  ms2_param_failure_count < ms2_param_total_count.
proof.
rewrite /ms2_param_total_count.
by smt(ms2_param_clean_count_pos).
qed.

op epsilon_ms_rom_programmability_parameterized : real =
  ms2_param_failure_count%r / ms2_param_total_count%r.

lemma epsilon_ms_rom_programmability_parameterized_closed_form :
  epsilon_ms_rom_programmability_parameterized =
  ms2_param_failure_count%r / ms2_param_total_count%r.
proof. by rewrite /epsilon_ms_rom_programmability_parameterized. qed.

lemma epsilon_ms_rom_programmability_parameterized_nonneg :
  0%r <= epsilon_ms_rom_programmability_parameterized.
proof.
rewrite epsilon_ms_rom_programmability_parameterized_closed_form.
by smt(ms2_param_failure_count_nonneg ms2_param_total_count_pos).
qed.

op le_rej_param_soft_repair_count : int =
  1.

op le_rej_param_hard_repair_count : int =
  1.

op le_rej_param_invalid_count : int =
  1.

op le_rej_param_accept_count : int =
  29.

op le_rej_param_failure_count : int =
  le_rej_param_soft_repair_count +
  le_rej_param_hard_repair_count +
  le_rej_param_invalid_count.

op le_rej_param_total_count : int =
  le_rej_param_accept_count + le_rej_param_failure_count.

lemma le_rej_param_failure_count_component_sum :
  le_rej_param_failure_count =
  le_rej_param_soft_repair_count +
  le_rej_param_hard_repair_count +
  le_rej_param_invalid_count.
proof. by rewrite /le_rej_param_failure_count. qed.

lemma le_rej_param_soft_repair_count_nonneg :
  0 <= le_rej_param_soft_repair_count.
proof.
rewrite /le_rej_param_soft_repair_count.
by smt().
qed.

lemma le_rej_param_hard_repair_count_nonneg :
  0 <= le_rej_param_hard_repair_count.
proof.
rewrite /le_rej_param_hard_repair_count.
by smt().
qed.

lemma le_rej_param_invalid_count_nonneg :
  0 <= le_rej_param_invalid_count.
proof.
rewrite /le_rej_param_invalid_count.
by smt().
qed.

lemma le_rej_param_accept_count_nonneg :
  0 <= le_rej_param_accept_count.
proof.
rewrite /le_rej_param_accept_count.
by smt().
qed.

lemma le_rej_param_accept_count_pos :
  0 < le_rej_param_accept_count.
proof.
rewrite /le_rej_param_accept_count.
by smt().
qed.

lemma le_rej_param_failure_count_nonneg :
  0 <= le_rej_param_failure_count.
proof.
rewrite /le_rej_param_failure_count.
by smt(le_rej_param_soft_repair_count_nonneg
       le_rej_param_hard_repair_count_nonneg
       le_rej_param_invalid_count_nonneg).
qed.

lemma le_rej_param_total_count_nonneg :
  0 <= le_rej_param_total_count.
proof.
rewrite /le_rej_param_total_count.
by smt(le_rej_param_accept_count_nonneg le_rej_param_failure_count_nonneg).
qed.

lemma le_rej_param_total_count_pos :
  0 < le_rej_param_total_count.
proof.
rewrite /le_rej_param_total_count.
by smt(le_rej_param_accept_count_pos le_rej_param_failure_count_nonneg).
qed.

lemma le_rej_param_failure_count_le_total_count :
  le_rej_param_failure_count <= le_rej_param_total_count.
proof.
rewrite /le_rej_param_total_count.
by smt(le_rej_param_accept_count_nonneg).
qed.

op epsilon_le_rej_parameterized : real =
  le_rej_param_failure_count%r / le_rej_param_total_count%r.

lemma epsilon_le_rej_parameterized_closed_form :
  epsilon_le_rej_parameterized =
  le_rej_param_failure_count%r / le_rej_param_total_count%r.
proof. by rewrite /epsilon_le_rej_parameterized. qed.

lemma epsilon_le_rej_parameterized_nonneg :
  0%r <= epsilon_le_rej_parameterized.
proof.
rewrite epsilon_le_rej_parameterized_closed_form.
by smt(le_rej_param_failure_count_nonneg le_rej_param_total_count_pos).
qed.

op le_fs_param_query_collision_count : int =
  BudgetParameters.le_fs_query_collision_slot_count.

op le_fs_param_programming_collision_count : int =
  BudgetParameters.le_fs_programming_collision_slot_count.

op le_fs_param_transcript_count : int =
  BudgetParameters.le_fs_transcript_mismatch_slot_count.

op le_fs_param_clean_count : int =
  BudgetParameters.le_fs_clean_slot_count.

op le_fs_param_failure_count : int =
  le_fs_param_query_collision_count +
  le_fs_param_programming_collision_count +
  le_fs_param_transcript_count.

op le_fs_param_total_count : int =
  le_fs_param_clean_count + le_fs_param_failure_count.

lemma le_fs_param_failure_count_component_sum :
  le_fs_param_failure_count =
  le_fs_param_query_collision_count +
  le_fs_param_programming_collision_count +
  le_fs_param_transcript_count.
proof. by rewrite /le_fs_param_failure_count. qed.

lemma le_fs_param_query_collision_count_nonneg :
  0 <= le_fs_param_query_collision_count.
proof.
rewrite /le_fs_param_query_collision_count.
exact BudgetParameters.le_fs_query_collision_slot_count_nonneg.
qed.

lemma le_fs_param_programming_collision_count_nonneg :
  0 <= le_fs_param_programming_collision_count.
proof.
rewrite /le_fs_param_programming_collision_count.
exact BudgetParameters.le_fs_programming_collision_slot_count_nonneg.
qed.

lemma le_fs_param_transcript_count_nonneg :
  0 <= le_fs_param_transcript_count.
proof.
rewrite /le_fs_param_transcript_count.
exact BudgetParameters.le_fs_transcript_mismatch_slot_count_nonneg.
qed.

lemma le_fs_param_clean_count_nonneg :
  0 <= le_fs_param_clean_count.
proof.
rewrite /le_fs_param_clean_count.
exact BudgetParameters.le_fs_clean_slot_count_nonneg.
qed.

lemma le_fs_param_clean_count_pos :
  0 < le_fs_param_clean_count.
proof.
rewrite /le_fs_param_clean_count.
exact BudgetParameters.le_fs_clean_slot_count_pos.
qed.

lemma le_fs_param_failure_count_nonneg :
  0 <= le_fs_param_failure_count.
proof.
rewrite /le_fs_param_failure_count.
by smt(le_fs_param_query_collision_count_nonneg
       le_fs_param_programming_collision_count_nonneg
       le_fs_param_transcript_count_nonneg).
qed.

lemma le_fs_param_total_count_nonneg :
  0 <= le_fs_param_total_count.
proof.
rewrite /le_fs_param_total_count.
by smt(le_fs_param_clean_count_nonneg le_fs_param_failure_count_nonneg).
qed.

lemma le_fs_param_total_count_pos :
  0 < le_fs_param_total_count.
proof.
rewrite /le_fs_param_total_count.
by smt(le_fs_param_clean_count_pos le_fs_param_failure_count_nonneg).
qed.

lemma le_fs_param_failure_count_le_total_count :
  le_fs_param_failure_count <= le_fs_param_total_count.
proof.
rewrite /le_fs_param_total_count.
by smt(le_fs_param_clean_count_nonneg).
qed.

op epsilon_le_fs_parameterized : real =
  le_fs_param_failure_count%r / le_fs_param_total_count%r.

lemma epsilon_le_fs_parameterized_closed_form :
  epsilon_le_fs_parameterized =
  le_fs_param_failure_count%r / le_fs_param_total_count%r.
proof. by rewrite /epsilon_le_fs_parameterized. qed.

lemma epsilon_le_fs_parameterized_nonneg :
  0%r <= epsilon_le_fs_parameterized.
proof.
rewrite epsilon_le_fs_parameterized_closed_form.
by smt(le_fs_param_failure_count_nonneg le_fs_param_total_count_pos).
qed.

op epsilon_le_parameterized : real =
  epsilon_le_rej_parameterized + epsilon_le_fs_parameterized.

lemma epsilon_le_parameterized_component_sum :
  epsilon_le_parameterized =
  epsilon_le_rej_parameterized + epsilon_le_fs_parameterized.
proof. by rewrite /epsilon_le_parameterized. qed.

lemma epsilon_le_parameterized_nonneg :
  0%r <= epsilon_le_parameterized.
proof.
rewrite /epsilon_le_parameterized.
by smt(epsilon_le_rej_parameterized_nonneg epsilon_le_fs_parameterized_nonneg).
qed.