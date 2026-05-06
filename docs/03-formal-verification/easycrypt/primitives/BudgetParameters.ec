require import AllCore Distr List IntDiv.

import Ring.IntID StdOrder.IntOrder Range.

(* Concrete zero-budget model.

   At the current abstraction level every transition that these budgets bound
   is already proved by an exact distribution / statistical-distance equality:

   - MS1 hash-binding: `L_ms1_hash_binding_stage_zero` proves the Real and
     AfterBinding observable distributions are equal.
   - Parallel semantic MS1 hash-binding owner:
     `epsilon_ms_hash_binding_semantic` now records a primitive-owned semantic
     hash-binding surrogate law with categories `clean`, `collision`,
     `malformed_binding`, and `transcript_mismatch`, failure predicate
     “non-clean”, and demo slot counts `13,1,1,1`, so it currently closes to
     `3%r / 16%r`. The active theorem-facing MS1 budget remains
     `epsilon_ms_hash_binding = 0%r` until an execution-owned MS1 semantic
     bridge exists.
   - MS2 ROM-programming: `L_ms2_rom_programming_transition_zero` proves the
     AfterBinding and AfterRom observable distributions are equal.
   - Parallel semantic MS ROM owner: `epsilon_ms_rom_programmability_semantic`
     now records a primitive-owned semantic ROM-programming surrogate law with
     categories `clean`, `query_collision`, `programming_collision`, and
     `transcript_mismatch`, failure predicate “non-clean”, and demo slot
     counts `13,1,1,1`, so it currently closes to `3%r / 16%r`. The active
     theorem-facing MS budget remains `epsilon_ms_rom_programmability = 0%r`
     until an execution-owned MS2 semantic bridge exists.
   - Shadow LE rejection component on the exact-zero route: `epsilon_le_rej`
     remains the active exact-zero lower rejection budget and stays at `0%r`.
   - Shadow LE rejection component on the semantic route:
     `epsilon_le_rej_semantic` tracks the lower rejection failure quantity used
     by the semantic theorem path. It is now presented as a primitive-owned
     semantic ticket-failure law: the probability that the primitive semantic
     rejection ticket requires hidden-query-material repair. The current
     primitive ticket law is owned by the named count constants
     `le_rej_soft_repair_slot_count`, `le_rej_hard_repair_slot_count`,
     `le_rej_invalid_slot_count`, and `le_rej_accept_slot_count`, which
     currently instantiate to `1,1,1,13`, so `epsilon_le_rej_semantic`
     currently closes to `3%r / 16%r`.
   - Shadow LE FS component: `epsilon_le_fs` is still `0%r`, but now for a
     semantic reason rather than only as a placeholder. The active
     branch-sensitive shadow lane measures failure by the shadow bad-branch
     condition on the post-constructor state, and that event is still proved
     impossible on the current concrete support because
     `d_le_pre_fs_programming_view x s` remains a `dunit` push-forward of
     `le_real_execution_observable x s` and the concrete real query material
     fixes `leqm_bad_flag = false`. In parallel, `epsilon_le_fs_semantic` is
     now presented as a primitive-owned structured branch/programming law with
     categories `clean`, `query_collision`, `programming_collision`, and
    `transcript_mismatch`, failure predicate “non-clean”, and demo slot
    counts `13,1,1,1`, so it currently closes to `3%r / 16%r`.
   - LE HVZK umbrella budget: `epsilon_le` is now defined as the sum of the
     lower component budgets `epsilon_le_rej + epsilon_le_fs`. In the current
     model both component lanes are still exact-zero, so the LE real and sim
     view distributions coincide and the umbrella bound is also identically 0.
   - Semantic LE umbrella budget: `epsilon_le_semantic` is defined as the sum
     of the semantic rejection and semantic FS components
     `epsilon_le_rej_semantic + epsilon_le_fs_semantic`. In the current model
     both semantic components currently close to `3%r / 16%r`, so the semantic
     umbrella currently evaluates to `3%r / 8%r`. This is a structured
     surrogate theorem budget, not a final cryptographic tightness claim.

  Therefore each active exact-zero budget is defined as `0%r`. This is NOT a
  nonzero cryptographic security bound; it records the exact-zero gap of the
  current model. Parallel semantic-owned LE budgets, a parallel semantic MS
  hash-binding owner, and a parallel semantic MS ROM owner may coexist beside
  that exact-zero route without changing it. Any future refinement that
  introduces a non-identity rejection sampler, a genuinely supported FS bad
  branch, a semantic MS1 bad-event model, or a quantitative ROM model on the
  active route must bridge those semantic owners into the theorem-facing path
  rather than redefining the exact-zero route in place. *)

op epsilon_ms_hash_binding : real = 0%r.

lemma A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.
proof. by rewrite /epsilon_ms_hash_binding. qed.

type ms_hash_binding_semantic_category = [
  | MSHashBindingSemanticClean
  | MSHashBindingSemanticCollision
  | MSHashBindingSemanticMalformedBinding
  | MSHashBindingSemanticTranscriptMismatch
].

op ms_hash_binding_semantic_category_support :
  ms_hash_binding_semantic_category list =
  [ MSHashBindingSemanticClean;
    MSHashBindingSemanticCollision;
    MSHashBindingSemanticMalformedBinding;
    MSHashBindingSemanticTranscriptMismatch ].

(* Primitive owner for a future semantic MS hash-binding budget.
   The active theorem-facing MS1 budget remains the exact-zero
   `epsilon_ms_hash_binding` on the current route. This parallel semantic
   skeleton records a structured category law without changing the theorem
   surface until an execution-owned MS1 semantic bridge exists. *)

lemma ms_hash_binding_semantic_category_support_uniq :
  uniq ms_hash_binding_semantic_category_support.
proof.
by rewrite /ms_hash_binding_semantic_category_support.
qed.

op ms_hash_binding_collision_slot_count : int = 1.

op ms_hash_binding_malformed_binding_slot_count : int = 1.

op ms_hash_binding_transcript_mismatch_slot_count : int = 1.

op ms_hash_binding_clean_slot_count : int = 13.

op ms_hash_binding_failure_slot_count : int =
  ms_hash_binding_collision_slot_count +
  ms_hash_binding_malformed_binding_slot_count +
  ms_hash_binding_transcript_mismatch_slot_count.

op ms_hash_binding_total_slot_count : int =
  ms_hash_binding_clean_slot_count + ms_hash_binding_failure_slot_count.

op ms_hash_binding_semantic_category_is_failure
  (category : ms_hash_binding_semantic_category) : bool =
  if pred1 MSHashBindingSemanticClean category then false else true.

lemma ms_hash_binding_collision_slot_count_nonneg :
  0 <= ms_hash_binding_collision_slot_count.
proof. by rewrite /ms_hash_binding_collision_slot_count. qed.

lemma ms_hash_binding_malformed_binding_slot_count_nonneg :
  0 <= ms_hash_binding_malformed_binding_slot_count.
proof. by rewrite /ms_hash_binding_malformed_binding_slot_count. qed.

lemma ms_hash_binding_transcript_mismatch_slot_count_nonneg :
  0 <= ms_hash_binding_transcript_mismatch_slot_count.
proof. by rewrite /ms_hash_binding_transcript_mismatch_slot_count. qed.

lemma ms_hash_binding_clean_slot_count_nonneg :
  0 <= ms_hash_binding_clean_slot_count.
proof. by rewrite /ms_hash_binding_clean_slot_count. qed.

lemma ms_hash_binding_clean_slot_count_pos :
  0 < ms_hash_binding_clean_slot_count.
proof. by rewrite /ms_hash_binding_clean_slot_count. qed.

lemma ms_hash_binding_failure_slot_count_nonneg :
  0 <= ms_hash_binding_failure_slot_count.
proof.
rewrite /ms_hash_binding_failure_slot_count.
by smt(ms_hash_binding_collision_slot_count_nonneg
       ms_hash_binding_malformed_binding_slot_count_nonneg
       ms_hash_binding_transcript_mismatch_slot_count_nonneg).
qed.

lemma ms_hash_binding_total_slot_count_nonneg :
  0 <= ms_hash_binding_total_slot_count.
proof.
rewrite /ms_hash_binding_total_slot_count.
by smt(ms_hash_binding_clean_slot_count_nonneg
       ms_hash_binding_failure_slot_count_nonneg).
qed.

lemma ms_hash_binding_total_slot_count_pos :
  0 < ms_hash_binding_total_slot_count.
proof.
rewrite /ms_hash_binding_total_slot_count.
by smt(ms_hash_binding_clean_slot_count_pos
       ms_hash_binding_failure_slot_count_nonneg).
qed.

lemma ms_hash_binding_failure_slot_count_pos :
  0 < ms_hash_binding_failure_slot_count.
proof.
rewrite /ms_hash_binding_failure_slot_count
  /ms_hash_binding_collision_slot_count
  /ms_hash_binding_malformed_binding_slot_count
  /ms_hash_binding_transcript_mismatch_slot_count.
by smt().
qed.

lemma ms_hash_binding_failure_slot_count_le_total_slot_count :
  ms_hash_binding_failure_slot_count <= ms_hash_binding_total_slot_count.
proof.
rewrite /ms_hash_binding_total_slot_count.
by smt(ms_hash_binding_clean_slot_count_nonneg).
qed.

lemma ms_hash_binding_failure_slot_count_lt_total_slot_count :
  ms_hash_binding_failure_slot_count < ms_hash_binding_total_slot_count.
proof.
rewrite /ms_hash_binding_total_slot_count.
by smt(ms_hash_binding_clean_slot_count_pos).
qed.

lemma ms_hash_binding_failure_slot_count_demo_closed_form :
  ms_hash_binding_failure_slot_count = 3.
proof.
rewrite /ms_hash_binding_failure_slot_count
  /ms_hash_binding_collision_slot_count
  /ms_hash_binding_malformed_binding_slot_count
  /ms_hash_binding_transcript_mismatch_slot_count.
by [].
qed.

lemma ms_hash_binding_total_slot_count_demo_closed_form :
  ms_hash_binding_total_slot_count = 16.
proof.
rewrite /ms_hash_binding_total_slot_count /ms_hash_binding_clean_slot_count.
by rewrite ms_hash_binding_failure_slot_count_demo_closed_form.
qed.

op epsilon_ms_hash_binding_semantic : real =
  ms_hash_binding_failure_slot_count%r / ms_hash_binding_total_slot_count%r.

lemma epsilon_ms_hash_binding_semantic_closed_form :
  epsilon_ms_hash_binding_semantic =
  ms_hash_binding_failure_slot_count%r / ms_hash_binding_total_slot_count%r.
proof. by rewrite /epsilon_ms_hash_binding_semantic. qed.

lemma epsilon_ms_hash_binding_semantic_demo_closed_form :
  epsilon_ms_hash_binding_semantic = 3%r / 16%r.
proof.
rewrite epsilon_ms_hash_binding_semantic_closed_form.
rewrite ms_hash_binding_failure_slot_count_demo_closed_form.
rewrite ms_hash_binding_total_slot_count_demo_closed_form.
by smt().
qed.

lemma A1_ms_hash_binding_semantic_nonneg :
  0%r <= epsilon_ms_hash_binding_semantic.
proof.
rewrite epsilon_ms_hash_binding_semantic_closed_form.
by smt().
qed.

op epsilon_ms_rom_programmability : real = 0%r.

lemma A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.
proof. by rewrite /epsilon_ms_rom_programmability. qed.

type ms_rom_semantic_category = [
  | MSROMSemanticClean
  | MSROMSemanticQueryCollision
  | MSROMSemanticProgrammingCollision
  | MSROMSemanticTranscriptMismatch
].

op ms_rom_semantic_category_support :
  ms_rom_semantic_category list =
  [ MSROMSemanticClean;
    MSROMSemanticQueryCollision;
    MSROMSemanticProgrammingCollision;
    MSROMSemanticTranscriptMismatch ].

(* Primitive owner for a future semantic MS ROM-programmability budget.
   The active theorem-facing MS2 budget remains the exact-zero
   `epsilon_ms_rom_programmability` on the current route. This parallel
   semantic skeleton records a structured category law without changing the
   theorem surface until an execution-owned MS2 semantic bridge exists. *)

lemma ms_rom_semantic_category_support_uniq :
  uniq ms_rom_semantic_category_support.
proof.
by rewrite /ms_rom_semantic_category_support.
qed.

op ms_rom_query_collision_slot_count : int = 1.

op ms_rom_programming_collision_slot_count : int = 1.

op ms_rom_transcript_mismatch_slot_count : int = 1.

op ms_rom_clean_slot_count : int = 13.

op ms_rom_failure_slot_count : int =
  ms_rom_query_collision_slot_count +
  ms_rom_programming_collision_slot_count +
  ms_rom_transcript_mismatch_slot_count.

op ms_rom_total_slot_count : int =
  ms_rom_clean_slot_count + ms_rom_failure_slot_count.

op ms_rom_semantic_category_is_failure
  (category : ms_rom_semantic_category) : bool =
  if pred1 MSROMSemanticClean category then false else true.

lemma ms_rom_query_collision_slot_count_nonneg :
  0 <= ms_rom_query_collision_slot_count.
proof. by rewrite /ms_rom_query_collision_slot_count. qed.

lemma ms_rom_programming_collision_slot_count_nonneg :
  0 <= ms_rom_programming_collision_slot_count.
proof. by rewrite /ms_rom_programming_collision_slot_count. qed.

lemma ms_rom_transcript_mismatch_slot_count_nonneg :
  0 <= ms_rom_transcript_mismatch_slot_count.
proof. by rewrite /ms_rom_transcript_mismatch_slot_count. qed.

lemma ms_rom_clean_slot_count_nonneg :
  0 <= ms_rom_clean_slot_count.
proof. by rewrite /ms_rom_clean_slot_count. qed.

lemma ms_rom_clean_slot_count_pos :
  0 < ms_rom_clean_slot_count.
proof. by rewrite /ms_rom_clean_slot_count. qed.

lemma ms_rom_failure_slot_count_nonneg :
  0 <= ms_rom_failure_slot_count.
proof.
rewrite /ms_rom_failure_slot_count.
by smt(ms_rom_query_collision_slot_count_nonneg
       ms_rom_programming_collision_slot_count_nonneg
       ms_rom_transcript_mismatch_slot_count_nonneg).
qed.

lemma ms_rom_total_slot_count_nonneg :
  0 <= ms_rom_total_slot_count.
proof.
rewrite /ms_rom_total_slot_count.
by smt(ms_rom_clean_slot_count_nonneg ms_rom_failure_slot_count_nonneg).
qed.

lemma ms_rom_total_slot_count_pos :
  0 < ms_rom_total_slot_count.
proof.
rewrite /ms_rom_total_slot_count.
by smt(ms_rom_clean_slot_count_pos ms_rom_failure_slot_count_nonneg).
qed.

lemma ms_rom_failure_slot_count_pos :
  0 < ms_rom_failure_slot_count.
proof.
rewrite /ms_rom_failure_slot_count
  /ms_rom_query_collision_slot_count
  /ms_rom_programming_collision_slot_count
  /ms_rom_transcript_mismatch_slot_count.
by smt().
qed.

lemma ms_rom_failure_slot_count_le_total_slot_count :
  ms_rom_failure_slot_count <= ms_rom_total_slot_count.
proof.
rewrite /ms_rom_total_slot_count.
by smt(ms_rom_clean_slot_count_nonneg).
qed.

lemma ms_rom_failure_slot_count_lt_total_slot_count :
  ms_rom_failure_slot_count < ms_rom_total_slot_count.
proof.
rewrite /ms_rom_total_slot_count.
by smt(ms_rom_clean_slot_count_pos).
qed.

lemma ms_rom_failure_slot_count_demo_closed_form :
  ms_rom_failure_slot_count = 3.
proof.
rewrite /ms_rom_failure_slot_count
  /ms_rom_query_collision_slot_count
  /ms_rom_programming_collision_slot_count
  /ms_rom_transcript_mismatch_slot_count.
by [].
qed.

lemma ms_rom_total_slot_count_demo_closed_form :
  ms_rom_total_slot_count = 16.
proof.
rewrite /ms_rom_total_slot_count /ms_rom_clean_slot_count.
by rewrite ms_rom_failure_slot_count_demo_closed_form.
qed.

op epsilon_ms_rom_programmability_semantic : real =
  ms_rom_failure_slot_count%r / ms_rom_total_slot_count%r.

lemma epsilon_ms_rom_programmability_semantic_closed_form :
  epsilon_ms_rom_programmability_semantic =
  ms_rom_failure_slot_count%r / ms_rom_total_slot_count%r.
proof. by rewrite /epsilon_ms_rom_programmability_semantic. qed.

lemma epsilon_ms_rom_programmability_semantic_demo_closed_form :
  epsilon_ms_rom_programmability_semantic = 3%r / 16%r.
proof.
rewrite epsilon_ms_rom_programmability_semantic_closed_form.
rewrite ms_rom_failure_slot_count_demo_closed_form.
rewrite ms_rom_total_slot_count_demo_closed_form.
by smt().
qed.

lemma A2_ms_rom_programmability_semantic_nonneg :
  0%r <= epsilon_ms_rom_programmability_semantic.
proof.
rewrite epsilon_ms_rom_programmability_semantic_closed_form.
by smt().
qed.

op epsilon_le_rej : real = 0%r.

lemma A4_le_rejection_nonneg :
  0%r <= epsilon_le_rej.
proof. by rewrite /epsilon_le_rej. qed.

type le_rejection_semantic_ticket_category = [
  | LERejectionSemanticTicketSoftRepair
  | LERejectionSemanticTicketHardRepair
  | LERejectionSemanticTicketInvalid
  | LERejectionSemanticTicketAccept
].

op le_rejection_semantic_ticket_category_support :
  le_rejection_semantic_ticket_category list =
  [ LERejectionSemanticTicketSoftRepair;
    LERejectionSemanticTicketHardRepair;
    LERejectionSemanticTicketInvalid;
    LERejectionSemanticTicketAccept ].

(* Primitive owner for the theorem-facing semantic rejection budget.
  The category support is meant to stay stable for theorem plumbing, while the
  current named count parameters remain structured surrogate/demo values that
  can be refined without changing the public theorem API. *)

lemma le_rejection_semantic_ticket_category_support_uniq :
  uniq le_rejection_semantic_ticket_category_support.
proof.
by rewrite /le_rejection_semantic_ticket_category_support.
qed.

op le_rejection_semantic_ticket_soft_repair_slot_count : int = 1.

op le_rejection_semantic_ticket_hard_repair_slot_count : int = 1.

op le_rejection_semantic_ticket_invalid_slot_count : int = 1.

op le_rejection_semantic_ticket_accept_slot_count : int = 13.

op le_rejection_semantic_ticket_failure_slot_count : int =
  le_rejection_semantic_ticket_soft_repair_slot_count +
  le_rejection_semantic_ticket_hard_repair_slot_count +
  le_rejection_semantic_ticket_invalid_slot_count.

op le_rejection_semantic_ticket_total_slot_count : int =
  le_rejection_semantic_ticket_failure_slot_count +
  le_rejection_semantic_ticket_accept_slot_count.

op le_rej_soft_repair_slot_count : int =
  le_rejection_semantic_ticket_soft_repair_slot_count.

op le_rej_hard_repair_slot_count : int =
  le_rejection_semantic_ticket_hard_repair_slot_count.

op le_rej_invalid_slot_count : int =
  le_rejection_semantic_ticket_invalid_slot_count.

op le_rej_accept_slot_count : int =
  le_rejection_semantic_ticket_accept_slot_count.

op le_rej_failure_slot_count : int =
  le_rej_soft_repair_slot_count +
  le_rej_hard_repair_slot_count +
  le_rej_invalid_slot_count.

op le_rej_total_slot_count : int =
  le_rej_accept_slot_count + le_rej_failure_slot_count.

lemma le_rej_soft_repair_slot_count_nonneg :
  0 <= le_rej_soft_repair_slot_count.
proof.
by rewrite /le_rej_soft_repair_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count.
qed.

lemma le_rej_hard_repair_slot_count_nonneg :
  0 <= le_rej_hard_repair_slot_count.
proof.
by rewrite /le_rej_hard_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count.
qed.

lemma le_rej_invalid_slot_count_nonneg :
  0 <= le_rej_invalid_slot_count.
proof.
by rewrite /le_rej_invalid_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count.
qed.

lemma le_rej_accept_slot_count_nonneg :
  0 <= le_rej_accept_slot_count.
proof.
by rewrite /le_rej_accept_slot_count
  /le_rejection_semantic_ticket_accept_slot_count.
qed.

lemma le_rej_accept_slot_count_pos :
  0 < le_rej_accept_slot_count.
proof.
by rewrite /le_rej_accept_slot_count
  /le_rejection_semantic_ticket_accept_slot_count.
qed.

lemma le_rej_failure_slot_count_nonneg :
  0 <= le_rej_failure_slot_count.
proof.
rewrite /le_rej_failure_slot_count.
by smt(le_rej_soft_repair_slot_count_nonneg
       le_rej_hard_repair_slot_count_nonneg
       le_rej_invalid_slot_count_nonneg).
qed.

lemma le_rej_total_slot_count_nonneg :
  0 <= le_rej_total_slot_count.
proof.
rewrite /le_rej_total_slot_count.
by smt(le_rej_accept_slot_count_nonneg le_rej_failure_slot_count_nonneg).
qed.

lemma le_rej_total_slot_count_pos :
  0 < le_rej_total_slot_count.
proof.
rewrite /le_rej_total_slot_count.
by smt(le_rej_accept_slot_count_pos le_rej_failure_slot_count_nonneg).
qed.

lemma le_rej_failure_slot_count_pos :
  0 < le_rej_failure_slot_count.
proof.
rewrite /le_rej_failure_slot_count
  /le_rej_soft_repair_slot_count
  /le_rej_hard_repair_slot_count
  /le_rej_invalid_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count.
by [].
qed.

lemma le_rej_failure_slot_count_le_total_slot_count :
  le_rej_failure_slot_count <= le_rej_total_slot_count.
proof.
rewrite /le_rej_total_slot_count.
by smt(le_rej_accept_slot_count_nonneg).
qed.

lemma le_rej_failure_slot_count_lt_total_slot_count :
  le_rej_failure_slot_count < le_rej_total_slot_count.
proof.
rewrite /le_rej_total_slot_count.
by smt(le_rej_accept_slot_count_pos).
qed.

lemma le_rej_failure_slot_count_demo_closed_form :
  le_rej_failure_slot_count = 3.
proof.
rewrite /le_rej_failure_slot_count
  /le_rej_soft_repair_slot_count
  /le_rej_hard_repair_slot_count
  /le_rej_invalid_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count.
by [].
qed.

lemma le_rej_total_slot_count_demo_closed_form :
  le_rej_total_slot_count = 16.
proof.
rewrite /le_rej_total_slot_count /le_rej_accept_slot_count.
rewrite /le_rejection_semantic_ticket_accept_slot_count.
by rewrite le_rej_failure_slot_count_demo_closed_form.
qed.

lemma le_rejection_semantic_ticket_total_slot_count_pos :
  0 < le_rejection_semantic_ticket_total_slot_count.
proof.
by rewrite /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count.
qed.

lemma le_rejection_semantic_ticket_failure_slot_count_pos :
  0 < le_rejection_semantic_ticket_failure_slot_count.
proof.
by rewrite /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count.
qed.

lemma le_rejection_semantic_ticket_failure_slot_count_lt_total_slot_count :
  le_rejection_semantic_ticket_failure_slot_count <
  le_rejection_semantic_ticket_total_slot_count.
proof.
by rewrite /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count.
qed.

op le_rejection_semantic_total_slot_count : int =
  le_rej_total_slot_count.

op le_rejection_semantic_reject_slot_count : int =
  le_rej_failure_slot_count.

lemma le_rejection_semantic_total_slot_count_pos :
  0 < le_rejection_semantic_total_slot_count.
proof.
rewrite /le_rejection_semantic_total_slot_count.
exact le_rej_total_slot_count_pos.
qed.

lemma le_rejection_semantic_reject_slot_count_pos :
  0 < le_rejection_semantic_reject_slot_count.
proof.
rewrite /le_rejection_semantic_reject_slot_count.
exact le_rej_failure_slot_count_pos.
qed.

lemma le_rejection_semantic_reject_slot_count_lt_total_slot_count :
  le_rejection_semantic_reject_slot_count < le_rejection_semantic_total_slot_count.
proof.
rewrite /le_rejection_semantic_reject_slot_count /le_rejection_semantic_total_slot_count.
exact le_rej_failure_slot_count_lt_total_slot_count.
qed.

op le_rejection_semantic_ticket_slot_support : int list =
  range 0 le_rejection_semantic_ticket_total_slot_count.

lemma le_rejection_semantic_ticket_slot_supportE :
  le_rejection_semantic_ticket_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /le_rejection_semantic_ticket_slot_support
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count.
rewrite (range_ltn 0 16) 1:/# /=.
rewrite (range_ltn 1 16) 1:/# /=.
rewrite (range_ltn 2 16) 1:/# /=.
rewrite (range_ltn 3 16) 1:/# /=.
rewrite (range_ltn 4 16) 1:/# /=.
rewrite (range_ltn 5 16) 1:/# /=.
rewrite (range_ltn 6 16) 1:/# /=.
rewrite (range_ltn 7 16) 1:/# /=.
rewrite (range_ltn 8 16) 1:/# /=.
rewrite (range_ltn 9 16) 1:/# /=.
rewrite (range_ltn 10 16) 1:/# /=.
rewrite (range_ltn 11 16) 1:/# /=.
rewrite (range_ltn 12 16) 1:/# /=.
rewrite (range_ltn 13 16) 1:/# /=.
rewrite (range_ltn 14 16) 1:/# /=.
rewrite (range_ltn 15 16) 1:/# /=.
by rewrite range_geq /=.
qed.

lemma le_rejection_semantic_ticket_slot_support_uniq :
  uniq le_rejection_semantic_ticket_slot_support.
proof.
by rewrite /le_rejection_semantic_ticket_slot_support range_uniq.
qed.

op le_rejection_semantic_branch_slot_support : int list =
  le_rejection_semantic_ticket_slot_support.

lemma le_rejection_semantic_branch_slot_supportE :
  le_rejection_semantic_branch_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
exact le_rejection_semantic_ticket_slot_supportE.
qed.

lemma le_rejection_semantic_branch_slot_support_uniq :
  uniq le_rejection_semantic_branch_slot_support.
proof.
rewrite /le_rejection_semantic_branch_slot_support.
exact le_rejection_semantic_ticket_slot_support_uniq.
qed.

op le_rejection_semantic_ticket_category_of_slot
  (slot : int) : le_rejection_semantic_ticket_category =
  if slot < le_rejection_semantic_ticket_soft_repair_slot_count then
    LERejectionSemanticTicketSoftRepair
  else if slot <
      le_rejection_semantic_ticket_soft_repair_slot_count +
      le_rejection_semantic_ticket_hard_repair_slot_count then
    LERejectionSemanticTicketHardRepair
  else if slot < le_rejection_semantic_ticket_failure_slot_count then
    LERejectionSemanticTicketInvalid
  else LERejectionSemanticTicketAccept.

op le_rejection_semantic_ticket_category_is_failure
  (category : le_rejection_semantic_ticket_category) : bool =
  if pred1 LERejectionSemanticTicketAccept category then false else true.

op le_rejection_semantic_reject_branch_slot (slot : int) : bool =
  le_rejection_semantic_ticket_category_is_failure
    (le_rejection_semantic_ticket_category_of_slot slot).

op le_rejection_semantic_ticket_requires_repair_slot (slot : int) : bool =
  le_rejection_semantic_reject_branch_slot slot.

op d_le_rejection_semantic_ticket_slot_choice : int distr =
  duniform le_rejection_semantic_ticket_slot_support.

op d_le_rejection_semantic_branch_slot_choice : int distr =
  d_le_rejection_semantic_ticket_slot_choice.

lemma le_rejection_semantic_branch_slot_choice_lossless :
  is_lossless d_le_rejection_semantic_branch_slot_choice.
proof.
rewrite /d_le_rejection_semantic_branch_slot_choice.
rewrite /d_le_rejection_semantic_ticket_slot_choice.
rewrite /le_rejection_semantic_ticket_slot_support.
by apply duniform_ll; rewrite range_ltn /le_rejection_semantic_ticket_total_slot_count.
qed.

op d_le_rejection_semantic_ticket_category_choice :
  le_rejection_semantic_ticket_category distr =
  dmap d_le_rejection_semantic_ticket_slot_choice
    le_rejection_semantic_ticket_category_of_slot.

lemma le_rejection_semantic_ticket_category_choice_lossless :
  is_lossless d_le_rejection_semantic_ticket_category_choice.
proof.
rewrite /d_le_rejection_semantic_ticket_category_choice.
by apply dmap_ll; exact le_rejection_semantic_branch_slot_choice_lossless.
qed.

lemma le_rejection_semantic_ticket_category_choice_mass_soft_repair :
  mu1 d_le_rejection_semantic_ticket_category_choice LERejectionSemanticTicketSoftRepair =
  le_rejection_semantic_ticket_soft_repair_slot_count%r /
  le_rejection_semantic_ticket_total_slot_count%r.
proof.
rewrite /mu1 /d_le_rejection_semantic_ticket_category_choice dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 LERejectionSemanticTicketSoftRepair \o
      le_rejection_semantic_ticket_category_of_slot)
      le_rejection_semantic_ticket_slot_support = 1.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_category_of_slot
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count /=.
by smt().
qed.

lemma le_rejection_semantic_ticket_category_choice_mass_hard_repair :
  mu1 d_le_rejection_semantic_ticket_category_choice LERejectionSemanticTicketHardRepair =
  le_rejection_semantic_ticket_hard_repair_slot_count%r /
  le_rejection_semantic_ticket_total_slot_count%r.
proof.
rewrite /mu1 /d_le_rejection_semantic_ticket_category_choice dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 LERejectionSemanticTicketHardRepair \o
      le_rejection_semantic_ticket_category_of_slot)
      le_rejection_semantic_ticket_slot_support = 1.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_category_of_slot
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count /=.
by smt().
qed.

lemma le_rejection_semantic_ticket_category_choice_mass_invalid :
  mu1 d_le_rejection_semantic_ticket_category_choice LERejectionSemanticTicketInvalid =
  le_rejection_semantic_ticket_invalid_slot_count%r /
  le_rejection_semantic_ticket_total_slot_count%r.
proof.
rewrite /mu1 /d_le_rejection_semantic_ticket_category_choice dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 LERejectionSemanticTicketInvalid \o
      le_rejection_semantic_ticket_category_of_slot)
      le_rejection_semantic_ticket_slot_support = 1.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_category_of_slot
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_accept_slot_count /=.
by smt().
qed.

lemma le_rejection_semantic_ticket_category_choice_mass_accept :
  mu1 d_le_rejection_semantic_ticket_category_choice LERejectionSemanticTicketAccept =
  le_rejection_semantic_ticket_accept_slot_count%r /
  le_rejection_semantic_ticket_total_slot_count%r.
proof.
rewrite /mu1 /d_le_rejection_semantic_ticket_category_choice dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 LERejectionSemanticTicketAccept \o
      le_rejection_semantic_ticket_category_of_slot)
      le_rejection_semantic_ticket_slot_support = 13.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_category_of_slot
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_ticket_accept_slot_count
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count /=.
by smt().
qed.

op le_rejection_semantic_branch_support : bool list = [false; true].

lemma le_rejection_semantic_branch_support_uniq :
  uniq le_rejection_semantic_branch_support.
proof. by rewrite /le_rejection_semantic_branch_support. qed.

op d_le_rejection_semantic_ticket_repair_choice : bool distr =
  dmap d_le_rejection_semantic_ticket_category_choice
    le_rejection_semantic_ticket_category_is_failure.

lemma d_le_rejection_semantic_ticket_repair_choiceE :
  d_le_rejection_semantic_ticket_repair_choice =
  dmap d_le_rejection_semantic_ticket_slot_choice
    le_rejection_semantic_ticket_requires_repair_slot.
proof.
rewrite /d_le_rejection_semantic_ticket_repair_choice.
rewrite /d_le_rejection_semantic_ticket_category_choice.
rewrite (dmap_comp le_rejection_semantic_ticket_category_of_slot
  le_rejection_semantic_ticket_category_is_failure
  d_le_rejection_semantic_ticket_slot_choice).
have Hmap :
  dmap d_le_rejection_semantic_ticket_slot_choice
    (le_rejection_semantic_ticket_category_is_failure \o
      le_rejection_semantic_ticket_category_of_slot) =
  dmap d_le_rejection_semantic_ticket_slot_choice
    le_rejection_semantic_ticket_requires_repair_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /le_rejection_semantic_ticket_requires_repair_slot /(\o).
rewrite Hmap.
by [].
qed.

op d_le_rejection_semantic_branch_choice : bool distr =
  d_le_rejection_semantic_ticket_repair_choice.

lemma le_rejection_semantic_branch_choice_lossless :
  is_lossless d_le_rejection_semantic_branch_choice.
proof.
rewrite /d_le_rejection_semantic_branch_choice.
rewrite d_le_rejection_semantic_ticket_repair_choiceE.
by apply dmap_ll; exact le_rejection_semantic_branch_slot_choice_lossless.
qed.

lemma le_rejection_semantic_accept_branch_has_support :
  false \in d_le_rejection_semantic_branch_choice.
proof.
rewrite /d_le_rejection_semantic_branch_choice.
rewrite d_le_rejection_semantic_ticket_repair_choiceE.
apply/supp_dmap.
exists le_rejection_semantic_reject_slot_count; split.
  rewrite /d_le_rejection_semantic_ticket_slot_choice.
  rewrite /le_rejection_semantic_ticket_slot_support.
  rewrite supp_duniform mem_range.
  split; first smt(le_rejection_semantic_reject_slot_count_pos).
  smt(le_rejection_semantic_reject_slot_count_lt_total_slot_count).
by rewrite /le_rejection_semantic_ticket_requires_repair_slot
  /le_rejection_semantic_reject_branch_slot
  /le_rejection_semantic_ticket_category_is_failure
  /le_rejection_semantic_ticket_category_of_slot
  /le_rejection_semantic_reject_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count /pred1 ltrr.
qed.

lemma le_rejection_semantic_reject_branch_has_support :
  true \in d_le_rejection_semantic_branch_choice.
proof.
rewrite /d_le_rejection_semantic_branch_choice.
rewrite d_le_rejection_semantic_ticket_repair_choiceE.
apply/supp_dmap.
exists 0; split.
  rewrite /d_le_rejection_semantic_ticket_slot_choice.
  rewrite /le_rejection_semantic_ticket_slot_support.
  by rewrite supp_duniform mem_range /le_rejection_semantic_ticket_total_slot_count.
by rewrite /le_rejection_semantic_ticket_requires_repair_slot
  /le_rejection_semantic_reject_branch_slot
  /le_rejection_semantic_ticket_category_is_failure
  /le_rejection_semantic_ticket_category_of_slot
  /le_rejection_semantic_ticket_soft_repair_slot_count /pred1.
qed.

lemma le_rejection_semantic_branch_choice_mass_false :
  mu1 d_le_rejection_semantic_branch_choice false =
  (le_rejection_semantic_total_slot_count -
   le_rejection_semantic_reject_slot_count)%r /
  le_rejection_semantic_total_slot_count%r.
proof.
rewrite /mu1 /d_le_rejection_semantic_branch_choice.
rewrite d_le_rejection_semantic_ticket_repair_choiceE dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 false \o le_rejection_semantic_ticket_requires_repair_slot)
      le_rejection_semantic_ticket_slot_support = 13.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_requires_repair_slot
    /le_rejection_semantic_reject_branch_slot
    /le_rejection_semantic_ticket_category_is_failure
    /le_rejection_semantic_ticket_category_of_slot /pred1 /(\o)
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_total_slot_count /le_rejection_semantic_reject_slot_count.
rewrite /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count /=.
by smt().
qed.

lemma le_rejection_semantic_branch_choice_mass_true :
  mu1 d_le_rejection_semantic_branch_choice true =
  le_rejection_semantic_reject_slot_count%r /
  le_rejection_semantic_total_slot_count%r.
proof.
rewrite /d_le_rejection_semantic_branch_choice.
rewrite /le_rejection_semantic_reject_slot_count /le_rejection_semantic_total_slot_count.
rewrite /d_le_rejection_semantic_ticket_repair_choice.
rewrite /mu1 dmapE /=.
rewrite /d_le_rejection_semantic_ticket_category_choice dmapE /=.
rewrite /d_le_rejection_semantic_ticket_slot_choice duniformE.
rewrite undup_id ?le_rejection_semantic_ticket_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o
      (le_rejection_semantic_ticket_category_is_failure \o
        le_rejection_semantic_ticket_category_of_slot))
      le_rejection_semantic_ticket_slot_support = 3.
  by rewrite le_rejection_semantic_ticket_slot_supportE
    /le_rejection_semantic_ticket_category_is_failure
    /le_rejection_semantic_ticket_category_of_slot
    /le_rejection_semantic_ticket_soft_repair_slot_count
    /le_rejection_semantic_ticket_hard_repair_slot_count
    /le_rejection_semantic_ticket_invalid_slot_count
    /le_rejection_semantic_ticket_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_rejection_semantic_ticket_slot_supportE /=.
rewrite /le_rejection_semantic_ticket_failure_slot_count
  /le_rejection_semantic_ticket_total_slot_count
  /le_rejection_semantic_ticket_soft_repair_slot_count
  /le_rejection_semantic_ticket_hard_repair_slot_count
  /le_rejection_semantic_ticket_invalid_slot_count
  /le_rejection_semantic_ticket_accept_slot_count /=.
by smt().
qed.

op le_rejection_semantic_ticket_failure_probability : real =
  mu1 d_le_rejection_semantic_ticket_repair_choice true.

lemma le_rejection_semantic_ticket_failure_probability_category_mass_sum :
  le_rejection_semantic_ticket_failure_probability =
  (le_rej_soft_repair_slot_count +
   le_rej_hard_repair_slot_count +
   le_rej_invalid_slot_count)%r /
  le_rej_total_slot_count%r.
proof.
rewrite /le_rejection_semantic_ticket_failure_probability.
rewrite le_rejection_semantic_branch_choice_mass_true.
rewrite /le_rejection_semantic_reject_slot_count /le_rejection_semantic_total_slot_count.
by rewrite /le_rej_failure_slot_count.
qed.

lemma le_rejection_semantic_ticket_failure_probability_closed_form :
  le_rejection_semantic_ticket_failure_probability =
  le_rej_failure_slot_count%r /
  le_rej_total_slot_count%r.
proof.
rewrite /le_rejection_semantic_ticket_failure_probability.
rewrite le_rejection_semantic_branch_choice_mass_true.
by rewrite /le_rejection_semantic_reject_slot_count /le_rejection_semantic_total_slot_count.
qed.

op epsilon_le_rej_semantic : real =
  le_rejection_semantic_ticket_failure_probability.

lemma epsilon_le_rej_semantic_is_ticket_failure_probability :
  epsilon_le_rej_semantic =
  le_rejection_semantic_ticket_failure_probability.
proof. by rewrite /epsilon_le_rej_semantic. qed.

lemma epsilon_le_rej_semantic_closed_form :
  epsilon_le_rej_semantic =
  le_rej_failure_slot_count%r /
  le_rej_total_slot_count%r.
proof.
rewrite /epsilon_le_rej_semantic.
exact le_rejection_semantic_ticket_failure_probability_closed_form.
qed.

lemma epsilon_le_rej_semantic_demo_closed_form :
  epsilon_le_rej_semantic = 3%r / 16%r.
proof.
rewrite epsilon_le_rej_semantic_closed_form.
rewrite le_rej_failure_slot_count_demo_closed_form.
rewrite le_rej_total_slot_count_demo_closed_form.
by smt().
qed.

lemma A4_le_rejection_semantic_nonneg :
  0%r <= epsilon_le_rej_semantic.
proof.
rewrite epsilon_le_rej_semantic_closed_form.
by smt().
qed.

op epsilon_le_fs : real = 0%r.

lemma A4_le_fs_nonneg :
  0%r <= epsilon_le_fs.
proof. by rewrite /epsilon_le_fs. qed.

type le_fs_semantic_branch_category = [
  | LEFSSemanticBranchClean
  | LEFSSemanticBranchQueryCollision
  | LEFSSemanticBranchProgrammingCollision
  | LEFSSemanticBranchTranscriptMismatch
].

op le_fs_semantic_branch_category_support :
  le_fs_semantic_branch_category list =
  [ LEFSSemanticBranchClean;
    LEFSSemanticBranchQueryCollision;
    LEFSSemanticBranchProgrammingCollision;
    LEFSSemanticBranchTranscriptMismatch ].

(* Primitive owner for the theorem-facing semantic FS budget.
   The category structure is now real, while the current slot masses remain
   structured surrogate/demo parameters that can be refined without changing
   the theorem-facing API. *)

lemma le_fs_semantic_branch_category_support_uniq :
  uniq le_fs_semantic_branch_category_support.
proof.
by rewrite /le_fs_semantic_branch_category_support.
qed.

op le_fs_query_collision_slot_count : int = 1.

op le_fs_programming_collision_slot_count : int = 1.

op le_fs_transcript_mismatch_slot_count : int = 1.

op le_fs_clean_slot_count : int = 13.

op le_fs_failure_slot_count : int =
  le_fs_query_collision_slot_count +
  le_fs_programming_collision_slot_count +
  le_fs_transcript_mismatch_slot_count.

op le_fs_total_slot_count : int =
  le_fs_clean_slot_count + le_fs_failure_slot_count.

op le_fs_semantic_query_collision_slot_count : int =
  le_fs_query_collision_slot_count.

op le_fs_semantic_programming_collision_slot_count : int =
  le_fs_programming_collision_slot_count.

op le_fs_semantic_transcript_mismatch_slot_count : int =
  le_fs_transcript_mismatch_slot_count.

op le_fs_semantic_clean_slot_count : int =
  le_fs_clean_slot_count.

op le_fs_semantic_failure_slot_count : int =
  le_fs_failure_slot_count.

op le_fs_semantic_total_slot_count : int =
  le_fs_total_slot_count.

lemma le_fs_query_collision_slot_count_nonneg :
  0 <= le_fs_query_collision_slot_count.
proof. by rewrite /le_fs_query_collision_slot_count. qed.

lemma le_fs_programming_collision_slot_count_nonneg :
  0 <= le_fs_programming_collision_slot_count.
proof. by rewrite /le_fs_programming_collision_slot_count. qed.

lemma le_fs_transcript_mismatch_slot_count_nonneg :
  0 <= le_fs_transcript_mismatch_slot_count.
proof. by rewrite /le_fs_transcript_mismatch_slot_count. qed.

lemma le_fs_clean_slot_count_nonneg :
  0 <= le_fs_clean_slot_count.
proof. by rewrite /le_fs_clean_slot_count. qed.

lemma le_fs_clean_slot_count_pos :
  0 < le_fs_clean_slot_count.
proof. by rewrite /le_fs_clean_slot_count. qed.

lemma le_fs_failure_slot_count_nonneg :
  0 <= le_fs_failure_slot_count.
proof.
rewrite /le_fs_failure_slot_count
  /le_fs_query_collision_slot_count
  /le_fs_programming_collision_slot_count
  /le_fs_transcript_mismatch_slot_count.
by smt().
qed.

lemma le_fs_total_slot_count_nonneg :
  0 <= le_fs_total_slot_count.
proof.
rewrite /le_fs_total_slot_count.
by smt(le_fs_clean_slot_count_nonneg le_fs_failure_slot_count_nonneg).
qed.

lemma le_fs_total_slot_count_pos :
  0 < le_fs_total_slot_count.
proof.
rewrite /le_fs_total_slot_count.
by smt(le_fs_clean_slot_count_pos le_fs_failure_slot_count_nonneg).
qed.

lemma le_fs_failure_slot_count_pos :
  0 < le_fs_failure_slot_count.
proof.
rewrite /le_fs_failure_slot_count
  /le_fs_query_collision_slot_count
  /le_fs_programming_collision_slot_count
  /le_fs_transcript_mismatch_slot_count.
by smt().
qed.

lemma le_fs_failure_slot_count_le_total_slot_count :
  le_fs_failure_slot_count <= le_fs_total_slot_count.
proof.
rewrite /le_fs_total_slot_count.
by smt(le_fs_clean_slot_count_nonneg).
qed.

lemma le_fs_failure_slot_count_lt_total_slot_count :
  le_fs_failure_slot_count < le_fs_total_slot_count.
proof.
rewrite /le_fs_total_slot_count.
by smt(le_fs_clean_slot_count_pos).
qed.

lemma le_fs_failure_slot_count_demo_closed_form :
  le_fs_failure_slot_count = 3.
proof.
rewrite /le_fs_failure_slot_count
  /le_fs_query_collision_slot_count
  /le_fs_programming_collision_slot_count
  /le_fs_transcript_mismatch_slot_count.
by [].
qed.

lemma le_fs_total_slot_count_demo_closed_form :
  le_fs_total_slot_count = 16.
proof.
rewrite /le_fs_total_slot_count /le_fs_clean_slot_count.
by rewrite le_fs_failure_slot_count_demo_closed_form.
qed.

lemma le_fs_semantic_total_slot_count_pos :
  0 < le_fs_semantic_total_slot_count.
proof.
rewrite /le_fs_semantic_total_slot_count.
exact le_fs_total_slot_count_pos.
qed.

lemma le_fs_semantic_failure_slot_count_pos :
  0 < le_fs_semantic_failure_slot_count.
proof.
rewrite /le_fs_semantic_failure_slot_count.
exact le_fs_failure_slot_count_pos.
qed.

lemma le_fs_semantic_failure_slot_count_lt_total_slot_count :
  le_fs_semantic_failure_slot_count < le_fs_semantic_total_slot_count.
proof.
rewrite /le_fs_semantic_failure_slot_count /le_fs_semantic_total_slot_count.
exact le_fs_failure_slot_count_lt_total_slot_count.
qed.

op total_slot_count : int = le_fs_total_slot_count.

op bad_slot_count : int = le_fs_failure_slot_count.

lemma total_slot_count_pos :
  0 < total_slot_count.
proof.
rewrite /total_slot_count.
exact le_fs_semantic_total_slot_count_pos.
qed.

lemma bad_slot_count_pos :
  0 < bad_slot_count.
proof.
rewrite /bad_slot_count.
exact le_fs_semantic_failure_slot_count_pos.
qed.

lemma bad_slot_count_lt_total_slot_count :
  bad_slot_count < total_slot_count.
proof.
rewrite /bad_slot_count /total_slot_count.
exact le_fs_semantic_failure_slot_count_lt_total_slot_count.
qed.

op le_fs_semantic_branch_slot_support : int list = range 0 total_slot_count.

lemma le_fs_semantic_branch_slot_supportE :
  le_fs_semantic_branch_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /le_fs_semantic_branch_slot_support /total_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form.
rewrite (range_ltn 0 16) 1:/# /=.
rewrite (range_ltn 1 16) 1:/# /=.
rewrite (range_ltn 2 16) 1:/# /=.
rewrite (range_ltn 3 16) 1:/# /=.
rewrite (range_ltn 4 16) 1:/# /=.
rewrite (range_ltn 5 16) 1:/# /=.
rewrite (range_ltn 6 16) 1:/# /=.
rewrite (range_ltn 7 16) 1:/# /=.
rewrite (range_ltn 8 16) 1:/# /=.
rewrite (range_ltn 9 16) 1:/# /=.
rewrite (range_ltn 10 16) 1:/# /=.
rewrite (range_ltn 11 16) 1:/# /=.
rewrite (range_ltn 12 16) 1:/# /=.
rewrite (range_ltn 13 16) 1:/# /=.
rewrite (range_ltn 14 16) 1:/# /=.
rewrite (range_ltn 15 16) 1:/# /=.
by rewrite range_geq /=.
qed.

lemma le_fs_semantic_branch_slot_support_uniq :
  uniq le_fs_semantic_branch_slot_support.
proof. by rewrite /le_fs_semantic_branch_slot_support range_uniq. qed.

op le_fs_semantic_branch_category_of_slot
  (slot : int) : le_fs_semantic_branch_category =
  if slot < le_fs_query_collision_slot_count then
    LEFSSemanticBranchQueryCollision
  else if slot <
      le_fs_query_collision_slot_count +
      le_fs_programming_collision_slot_count then
    LEFSSemanticBranchProgrammingCollision
  else if slot < le_fs_failure_slot_count then
    LEFSSemanticBranchTranscriptMismatch
  else LEFSSemanticBranchClean.

op le_fs_semantic_branch_category_is_failure
  (category : le_fs_semantic_branch_category) : bool =
  if pred1 LEFSSemanticBranchClean category then false else true.

op le_fs_semantic_bad_branch_slot (slot : int) : bool =
  le_fs_semantic_branch_category_is_failure
    (le_fs_semantic_branch_category_of_slot slot).

op d_le_fs_semantic_branch_slot_choice : int distr =
  duniform le_fs_semantic_branch_slot_support.

lemma le_fs_semantic_branch_slot_choice_lossless :
  is_lossless d_le_fs_semantic_branch_slot_choice.
proof.
rewrite /d_le_fs_semantic_branch_slot_choice.
rewrite le_fs_semantic_branch_slot_supportE.
by apply duniform_ll.
qed.

op d_le_fs_semantic_branch_category_choice :
  le_fs_semantic_branch_category distr =
  dmap d_le_fs_semantic_branch_slot_choice le_fs_semantic_branch_category_of_slot.

lemma le_fs_semantic_branch_category_choice_lossless :
  is_lossless d_le_fs_semantic_branch_category_choice.
proof.
rewrite /d_le_fs_semantic_branch_category_choice.
by apply dmap_ll; exact le_fs_semantic_branch_slot_choice_lossless.
qed.

lemma le_fs_semantic_branch_category_choice_mass_clean :
  mu1 d_le_fs_semantic_branch_category_choice LEFSSemanticBranchClean =
  le_fs_clean_slot_count%r /
  le_fs_total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_category_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 LEFSSemanticBranchClean \o
      le_fs_semantic_branch_category_of_slot)
      le_fs_semantic_branch_slot_support = 13.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_branch_category_of_slot
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite /le_fs_clean_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form /=.
by smt().
qed.

lemma le_fs_semantic_branch_category_choice_mass_query_collision :
  mu1 d_le_fs_semantic_branch_category_choice LEFSSemanticBranchQueryCollision =
  le_fs_query_collision_slot_count%r /
  le_fs_total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_category_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 LEFSSemanticBranchQueryCollision \o
      le_fs_semantic_branch_category_of_slot)
      le_fs_semantic_branch_slot_support = 1.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_branch_category_of_slot
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite /le_fs_query_collision_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form /=.
by smt().
qed.

lemma le_fs_semantic_branch_category_choice_mass_programming_collision :
  mu1 d_le_fs_semantic_branch_category_choice LEFSSemanticBranchProgrammingCollision =
  le_fs_programming_collision_slot_count%r /
  le_fs_total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_category_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 LEFSSemanticBranchProgrammingCollision \o
      le_fs_semantic_branch_category_of_slot)
      le_fs_semantic_branch_slot_support = 1.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_branch_category_of_slot
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite /le_fs_programming_collision_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form /=.
by smt().
qed.

lemma le_fs_semantic_branch_category_choice_mass_transcript_mismatch :
  mu1 d_le_fs_semantic_branch_category_choice LEFSSemanticBranchTranscriptMismatch =
  le_fs_transcript_mismatch_slot_count%r /
  le_fs_total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_category_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 LEFSSemanticBranchTranscriptMismatch \o
      le_fs_semantic_branch_category_of_slot)
      le_fs_semantic_branch_slot_support = 1.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_branch_category_of_slot
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite /le_fs_transcript_mismatch_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form /=.
by smt().
qed.

op le_fs_semantic_branch_support : bool list = [false; true].

lemma le_fs_semantic_branch_support_uniq :
  uniq le_fs_semantic_branch_support.
proof. by rewrite /le_fs_semantic_branch_support. qed.

op d_le_fs_semantic_branch_choice : bool distr =
  dmap d_le_fs_semantic_branch_category_choice
    le_fs_semantic_branch_category_is_failure.

lemma d_le_fs_semantic_branch_choiceE :
  d_le_fs_semantic_branch_choice =
  dmap d_le_fs_semantic_branch_slot_choice le_fs_semantic_bad_branch_slot.
proof.
rewrite /d_le_fs_semantic_branch_choice.
rewrite /d_le_fs_semantic_branch_category_choice.
rewrite (dmap_comp le_fs_semantic_branch_category_of_slot
  le_fs_semantic_branch_category_is_failure
  d_le_fs_semantic_branch_slot_choice).
have Hmap :
  dmap d_le_fs_semantic_branch_slot_choice
    (le_fs_semantic_branch_category_is_failure \o
      le_fs_semantic_branch_category_of_slot) =
  dmap d_le_fs_semantic_branch_slot_choice
    le_fs_semantic_bad_branch_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /le_fs_semantic_bad_branch_slot /(\o).
rewrite Hmap.
by [].
qed.

lemma le_fs_semantic_branch_choice_lossless :
  is_lossless d_le_fs_semantic_branch_choice.
proof.
rewrite /d_le_fs_semantic_branch_choice.
by apply dmap_ll; exact le_fs_semantic_branch_category_choice_lossless.
qed.

lemma le_fs_semantic_good_branch_has_support :
  false \in d_le_fs_semantic_branch_choice.
proof.
rewrite d_le_fs_semantic_branch_choiceE.
apply/supp_dmap.
exists bad_slot_count; split.
  rewrite /d_le_fs_semantic_branch_slot_choice /le_fs_semantic_branch_slot_support.
  rewrite supp_duniform mem_range.
  by split; first smt(bad_slot_count_pos); smt(bad_slot_count_lt_total_slot_count).
rewrite /le_fs_semantic_bad_branch_slot
  /le_fs_semantic_branch_category_is_failure
  /le_fs_semantic_branch_category_of_slot
  /le_fs_query_collision_slot_count
  /le_fs_programming_collision_slot_count
  /le_fs_transcript_mismatch_slot_count
  /le_fs_failure_slot_count /pred1 /=.
by [].
qed.

lemma le_fs_semantic_bad_branch_has_support :
  true \in d_le_fs_semantic_branch_choice.
proof.
rewrite d_le_fs_semantic_branch_choiceE.
apply/supp_dmap.
exists 0; split.
  rewrite /d_le_fs_semantic_branch_slot_choice /le_fs_semantic_branch_slot_support.
  by rewrite supp_duniform mem_range /total_slot_count.
rewrite /le_fs_semantic_bad_branch_slot
  /le_fs_semantic_branch_category_is_failure
  /le_fs_semantic_branch_category_of_slot
  /le_fs_query_collision_slot_count
  /le_fs_programming_collision_slot_count
  /le_fs_transcript_mismatch_slot_count
  /le_fs_failure_slot_count /pred1 /=.
by [].
qed.

lemma le_fs_semantic_branch_choice_mass_false :
  mu1 d_le_fs_semantic_branch_choice false =
  (total_slot_count - bad_slot_count)%r / total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_le_fs_semantic_branch_choiceE dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 false \o le_fs_semantic_bad_branch_slot)
      le_fs_semantic_branch_slot_support = 13.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_bad_branch_slot
    /le_fs_semantic_branch_category_is_failure
    /le_fs_semantic_branch_category_of_slot /pred1 /(\o)
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite /total_slot_count /bad_slot_count.
rewrite le_fs_total_slot_count_demo_closed_form.
rewrite le_fs_failure_slot_count_demo_closed_form /=.
by smt().
qed.

lemma le_fs_semantic_branch_choice_mass_true :
  mu1 d_le_fs_semantic_branch_choice true =
  bad_slot_count%r / total_slot_count%r.
proof.
rewrite /d_le_fs_semantic_branch_choice.
rewrite /bad_slot_count /total_slot_count.
rewrite /mu1 dmapE /=.
rewrite /d_le_fs_semantic_branch_category_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o
      (le_fs_semantic_branch_category_is_failure \o
        le_fs_semantic_branch_category_of_slot))
      le_fs_semantic_branch_slot_support = 3.
  by rewrite le_fs_semantic_branch_slot_supportE
    /le_fs_semantic_branch_category_is_failure
    /le_fs_semantic_branch_category_of_slot
    /le_fs_query_collision_slot_count
    /le_fs_programming_collision_slot_count
    /le_fs_transcript_mismatch_slot_count
    /le_fs_failure_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
rewrite le_fs_failure_slot_count_demo_closed_form.
rewrite le_fs_total_slot_count_demo_closed_form /=.
by smt().
qed.

op le_fs_semantic_failure_probability : real =
  mu1 d_le_fs_semantic_branch_choice true.

lemma le_fs_semantic_failure_probability_category_mass_sum :
  le_fs_semantic_failure_probability =
  le_fs_failure_slot_count%r / le_fs_total_slot_count%r.
proof.
rewrite /le_fs_semantic_failure_probability.
rewrite /bad_slot_count /total_slot_count.
rewrite /le_fs_failure_slot_count /le_fs_total_slot_count.
exact le_fs_semantic_branch_choice_mass_true.
qed.

lemma le_fs_semantic_failure_probability_closed_form :
  le_fs_semantic_failure_probability =
  le_fs_failure_slot_count%r / le_fs_total_slot_count%r.
proof.
rewrite /le_fs_semantic_failure_probability.
rewrite /bad_slot_count /total_slot_count.
exact le_fs_semantic_branch_choice_mass_true.
qed.

op epsilon_le_fs_semantic : real = le_fs_semantic_failure_probability.

lemma epsilon_le_fs_semantic_is_failure_probability :
  epsilon_le_fs_semantic = le_fs_semantic_failure_probability.
proof. by rewrite /epsilon_le_fs_semantic. qed.

lemma epsilon_le_fs_semantic_closed_form :
  epsilon_le_fs_semantic = le_fs_failure_slot_count%r / le_fs_total_slot_count%r.
proof.
rewrite /epsilon_le_fs_semantic.
exact le_fs_semantic_failure_probability_closed_form.
qed.

lemma epsilon_le_fs_semantic_demo_closed_form :
  epsilon_le_fs_semantic = 3%r / 16%r.
proof.
rewrite epsilon_le_fs_semantic_closed_form.
rewrite le_fs_failure_slot_count_demo_closed_form.
rewrite le_fs_total_slot_count_demo_closed_form.
by smt().
qed.

lemma A4_le_fs_semantic_nonneg :
  0%r <= epsilon_le_fs_semantic.
proof.
rewrite epsilon_le_fs_semantic_closed_form.
by smt().
qed.

op epsilon_le_semantic : real = epsilon_le_rej_semantic + epsilon_le_fs_semantic.

lemma epsilon_le_semantic_component_sum :
  epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic.
proof. by rewrite /epsilon_le_semantic. qed.

lemma epsilon_le_semantic_nonneg :
  0%r <= epsilon_le_semantic.
proof.
rewrite /epsilon_le_semantic /epsilon_le_rej_semantic /epsilon_le_fs_semantic.
by smt().
qed.

op epsilon_le : real = epsilon_le_rej + epsilon_le_fs.

lemma epsilon_le_component_sum :
  epsilon_le = epsilon_le_rej + epsilon_le_fs.
proof. by rewrite /epsilon_le. qed.

lemma A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.
proof.
rewrite /epsilon_le /epsilon_le_rej /epsilon_le_fs.
have -> : 0%r + 0%r = 0%r by ring.
by [].
qed.