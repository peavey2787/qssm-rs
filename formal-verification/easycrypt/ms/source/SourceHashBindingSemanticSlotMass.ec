require import AllCore Int List Distr.
require import BudgetParameters.
import Ring.IntID StdOrder.IntOrder Range.

(* Local slot/category choice and mass owner below
   `SourceHashBindingSemanticBridge.ec`. *)

op ms_hash_binding_semantic_slot_support : int list =
  range 0 BudgetParameters.ms_hash_binding_total_slot_count.

lemma ms_hash_binding_semantic_slot_supportE :
  ms_hash_binding_semantic_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /ms_hash_binding_semantic_slot_support.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form.
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

lemma ms_hash_binding_semantic_slot_support_uniq :
  uniq ms_hash_binding_semantic_slot_support.
proof. by rewrite /ms_hash_binding_semantic_slot_support range_uniq. qed.

op ms_hash_binding_semantic_category_of_slot
  (slot : int) : BudgetParameters.ms_hash_binding_semantic_category =
  if slot < BudgetParameters.ms_hash_binding_collision_slot_count then
    BudgetParameters.MSHashBindingSemanticCollision
  else if slot <
      BudgetParameters.ms_hash_binding_collision_slot_count +
      BudgetParameters.ms_hash_binding_malformed_binding_slot_count then
    BudgetParameters.MSHashBindingSemanticMalformedBinding
  else if slot < BudgetParameters.ms_hash_binding_failure_slot_count then
    BudgetParameters.MSHashBindingSemanticTranscriptMismatch
  else BudgetParameters.MSHashBindingSemanticClean.

op ms_hash_binding_semantic_bad_slot (slot : int) : bool =
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
    (ms_hash_binding_semantic_category_of_slot slot).

op d_ms_hash_binding_semantic_slot_choice : int distr =
  duniform ms_hash_binding_semantic_slot_support.

op d_ms_hash_binding_semantic_category_choice :
  BudgetParameters.ms_hash_binding_semantic_category distr =
  dmap d_ms_hash_binding_semantic_slot_choice
    ms_hash_binding_semantic_category_of_slot.

op d_ms_hash_binding_semantic_failure_choice : bool distr =
  dmap d_ms_hash_binding_semantic_category_choice
    BudgetParameters.ms_hash_binding_semantic_category_is_failure.

lemma ms_hash_binding_semantic_slot_choice_lossless :
  is_lossless d_ms_hash_binding_semantic_slot_choice.
proof.
rewrite /d_ms_hash_binding_semantic_slot_choice.
rewrite ms_hash_binding_semantic_slot_supportE.
by apply duniform_ll.
qed.

lemma d_ms_hash_binding_semantic_failure_choiceE :
  d_ms_hash_binding_semantic_failure_choice =
  dmap d_ms_hash_binding_semantic_slot_choice ms_hash_binding_semantic_bad_slot.
proof.
rewrite /d_ms_hash_binding_semantic_failure_choice.
rewrite /d_ms_hash_binding_semantic_category_choice.
rewrite (dmap_comp ms_hash_binding_semantic_category_of_slot
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
  d_ms_hash_binding_semantic_slot_choice).
have Hmap :
  dmap d_ms_hash_binding_semantic_slot_choice
    (BudgetParameters.ms_hash_binding_semantic_category_is_failure \o
      ms_hash_binding_semantic_category_of_slot) =
  dmap d_ms_hash_binding_semantic_slot_choice ms_hash_binding_semantic_bad_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /ms_hash_binding_semantic_bad_slot /(\o).
rewrite Hmap.
by [].
qed.

op ms_hash_binding_public_divergence_upper_category_event
  (category : BudgetParameters.ms_hash_binding_semantic_category) : bool =
  pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category ||
  pred1 BudgetParameters.MSHashBindingSemanticTranscriptMismatch category.

op ms_hash_binding_public_divergence_upper_slot (slot : int) : bool =
  ms_hash_binding_public_divergence_upper_category_event
    (ms_hash_binding_semantic_category_of_slot slot).

op d_ms_hash_binding_public_divergence_upper_choice : bool distr =
  dmap d_ms_hash_binding_semantic_category_choice
    ms_hash_binding_public_divergence_upper_category_event.

op ms_hash_binding_local_public_divergence_upper_mass : real =
  (BudgetParameters.ms_hash_binding_malformed_binding_slot_count +
   BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count)%r /
  BudgetParameters.ms_hash_binding_total_slot_count%r.

lemma d_ms_hash_binding_public_divergence_upper_choiceE :
  d_ms_hash_binding_public_divergence_upper_choice =
  dmap d_ms_hash_binding_semantic_slot_choice
    ms_hash_binding_public_divergence_upper_slot.
proof.
rewrite /d_ms_hash_binding_public_divergence_upper_choice.
rewrite /d_ms_hash_binding_semantic_category_choice.
rewrite (dmap_comp ms_hash_binding_semantic_category_of_slot
  ms_hash_binding_public_divergence_upper_category_event
  d_ms_hash_binding_semantic_slot_choice).
have Hmap :
  dmap d_ms_hash_binding_semantic_slot_choice
    (ms_hash_binding_public_divergence_upper_category_event \o
      ms_hash_binding_semantic_category_of_slot) =
  dmap d_ms_hash_binding_semantic_slot_choice
    ms_hash_binding_public_divergence_upper_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /ms_hash_binding_public_divergence_upper_slot /(\o).
rewrite Hmap.
by [].
qed.

lemma ms_hash_binding_public_divergence_upper_choice_mass_eq_local_upper_mass :
  mu1 d_ms_hash_binding_public_divergence_upper_choice true =
  ms_hash_binding_local_public_divergence_upper_mass.
proof.
rewrite /mu1.
rewrite d_ms_hash_binding_public_divergence_upper_choiceE dmapE /=.
rewrite /d_ms_hash_binding_semantic_slot_choice duniformE.
rewrite undup_id ?ms_hash_binding_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o ms_hash_binding_public_divergence_upper_slot)
      ms_hash_binding_semantic_slot_support = 2.
  by rewrite ms_hash_binding_semantic_slot_supportE
    /ms_hash_binding_public_divergence_upper_slot
    /ms_hash_binding_public_divergence_upper_category_event
    /ms_hash_binding_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_hash_binding_collision_slot_count
    /BudgetParameters.ms_hash_binding_malformed_binding_slot_count
    /BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count
    /BudgetParameters.ms_hash_binding_failure_slot_count /=.
rewrite Hcount ms_hash_binding_semantic_slot_supportE /=.
rewrite /ms_hash_binding_local_public_divergence_upper_mass.
rewrite /BudgetParameters.ms_hash_binding_malformed_binding_slot_count.
rewrite /BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form /=.
by smt().
qed.

lemma ms_hash_binding_local_public_divergence_upper_mass_demo_closed_form :
  ms_hash_binding_local_public_divergence_upper_mass = 1%r / 8%r.
proof.
rewrite /ms_hash_binding_local_public_divergence_upper_mass.
rewrite /BudgetParameters.ms_hash_binding_malformed_binding_slot_count.
rewrite /BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form /=.
by smt().
qed.

lemma ms_hash_binding_semantic_failure_choice_mass_true :
  mu1 d_ms_hash_binding_semantic_failure_choice true =
  BudgetParameters.ms_hash_binding_failure_slot_count%r /
  BudgetParameters.ms_hash_binding_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_hash_binding_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_hash_binding_semantic_slot_choice duniformE.
rewrite undup_id ?ms_hash_binding_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o ms_hash_binding_semantic_bad_slot)
      ms_hash_binding_semantic_slot_support = 3.
  by rewrite ms_hash_binding_semantic_slot_supportE
    /ms_hash_binding_semantic_bad_slot
    /BudgetParameters.ms_hash_binding_semantic_category_is_failure
    /ms_hash_binding_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_hash_binding_collision_slot_count
    /BudgetParameters.ms_hash_binding_malformed_binding_slot_count
    /BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count
    /BudgetParameters.ms_hash_binding_failure_slot_count /=.
rewrite Hcount ms_hash_binding_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_hash_binding_failure_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form /=.
by smt().
qed.

op ms_hash_binding_local_failure_mass : real =
  mu1 d_ms_hash_binding_semantic_failure_choice true.

lemma ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic :
  ms_hash_binding_local_failure_mass =
  BudgetParameters.epsilon_ms_hash_binding_semantic.
proof.
rewrite /ms_hash_binding_local_failure_mass.
rewrite ms_hash_binding_semantic_failure_choice_mass_true.
rewrite BudgetParameters.epsilon_ms_hash_binding_semantic_closed_form.
by [].
qed.

lemma ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_semantic :
  ms_hash_binding_local_failure_mass <=
  BudgetParameters.epsilon_ms_hash_binding_semantic.
proof.
rewrite ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic.
by [].
qed.