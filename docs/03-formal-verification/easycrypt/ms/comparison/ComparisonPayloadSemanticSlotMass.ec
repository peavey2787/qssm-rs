require import AllCore Int List Distr.
require import BudgetParameters.
import Ring.IntID StdOrder.IntOrder Range.

(* Local slot/category choice and mass owner below
   `ComparisonPayloadSemanticBridge.ec`. *)

op ms_rom_semantic_slot_support : int list =
  range 0 BudgetParameters.ms_rom_total_slot_count.

lemma ms_rom_semantic_slot_supportE :
  ms_rom_semantic_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /ms_rom_semantic_slot_support.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form.
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

lemma ms_rom_semantic_slot_support_uniq :
  uniq ms_rom_semantic_slot_support.
proof. by rewrite /ms_rom_semantic_slot_support range_uniq. qed.

op ms_rom_semantic_category_of_slot
  (slot : int) : BudgetParameters.ms_rom_semantic_category =
  if slot < BudgetParameters.ms_rom_query_collision_slot_count then
    BudgetParameters.MSROMSemanticQueryCollision
  else if slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count then
    BudgetParameters.MSROMSemanticProgrammingCollision
  else if slot < BudgetParameters.ms_rom_failure_slot_count then
    BudgetParameters.MSROMSemanticTranscriptMismatch
  else BudgetParameters.MSROMSemanticClean.

op ms_rom_semantic_bad_slot (slot : int) : bool =
  BudgetParameters.ms_rom_semantic_category_is_failure
    (ms_rom_semantic_category_of_slot slot).

op d_ms_rom_semantic_slot_choice : int distr =
  duniform ms_rom_semantic_slot_support.

op d_ms_rom_semantic_category_choice :
  BudgetParameters.ms_rom_semantic_category distr =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_category_of_slot.

op d_ms_rom_semantic_failure_choice : bool distr =
  dmap d_ms_rom_semantic_category_choice
    BudgetParameters.ms_rom_semantic_category_is_failure.

lemma ms_rom_semantic_slot_choice_lossless :
  is_lossless d_ms_rom_semantic_slot_choice.
proof.
rewrite /d_ms_rom_semantic_slot_choice.
rewrite ms_rom_semantic_slot_supportE.
by apply duniform_ll.
qed.

lemma d_ms_rom_semantic_failure_choiceE :
  d_ms_rom_semantic_failure_choice =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_bad_slot.
proof.
rewrite /d_ms_rom_semantic_failure_choice.
rewrite /d_ms_rom_semantic_category_choice.
rewrite (dmap_comp ms_rom_semantic_category_of_slot
  BudgetParameters.ms_rom_semantic_category_is_failure
  d_ms_rom_semantic_slot_choice).
have Hmap :
  dmap d_ms_rom_semantic_slot_choice
    (BudgetParameters.ms_rom_semantic_category_is_failure \o
      ms_rom_semantic_category_of_slot) =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_bad_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /ms_rom_semantic_bad_slot /(\o).
rewrite Hmap.
by [].
qed.

lemma ms_rom_semantic_category_choice_lossless :
  is_lossless d_ms_rom_semantic_category_choice.
proof.
rewrite /d_ms_rom_semantic_category_choice.
by apply dmap_ll; exact ms_rom_semantic_slot_choice_lossless.
qed.

lemma ms_rom_semantic_failure_choice_lossless :
  is_lossless d_ms_rom_semantic_failure_choice.
proof.
rewrite /d_ms_rom_semantic_failure_choice.
by apply dmap_ll; exact ms_rom_semantic_category_choice_lossless.
qed.

lemma ms_rom_semantic_failure_choice_mass_false :
  mu1 d_ms_rom_semantic_failure_choice false =
  (BudgetParameters.ms_rom_total_slot_count -
   BudgetParameters.ms_rom_failure_slot_count)%r /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_rom_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_rom_semantic_slot_choice duniformE.
rewrite undup_id ?ms_rom_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 false \o ms_rom_semantic_bad_slot)
      ms_rom_semantic_slot_support = 13.
  by rewrite ms_rom_semantic_slot_supportE
    /ms_rom_semantic_bad_slot
    /BudgetParameters.ms_rom_semantic_category_is_failure
    /ms_rom_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_rom_query_collision_slot_count
    /BudgetParameters.ms_rom_programming_collision_slot_count
    /BudgetParameters.ms_rom_transcript_mismatch_slot_count
    /BudgetParameters.ms_rom_failure_slot_count /=.
rewrite Hcount ms_rom_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_rom_failure_slot_count_demo_closed_form /=.
by smt().
qed.

lemma ms_rom_semantic_failure_choice_mass_true :
  mu1 d_ms_rom_semantic_failure_choice true =
  BudgetParameters.ms_rom_failure_slot_count%r /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_rom_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_rom_semantic_slot_choice duniformE.
rewrite undup_id ?ms_rom_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o ms_rom_semantic_bad_slot)
      ms_rom_semantic_slot_support = 3.
  by rewrite ms_rom_semantic_slot_supportE
    /ms_rom_semantic_bad_slot
    /BudgetParameters.ms_rom_semantic_category_is_failure
    /ms_rom_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_rom_query_collision_slot_count
    /BudgetParameters.ms_rom_programming_collision_slot_count
    /BudgetParameters.ms_rom_transcript_mismatch_slot_count
    /BudgetParameters.ms_rom_failure_slot_count /=.
rewrite Hcount ms_rom_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_rom_failure_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form /=.
by smt().
qed.

op ms_rom_local_failure_mass : real =
  mu1 d_ms_rom_semantic_failure_choice true.

lemma ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic :
  ms_rom_local_failure_mass =
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite /ms_rom_local_failure_mass.
rewrite ms_rom_semantic_failure_choice_mass_true.
rewrite BudgetParameters.epsilon_ms_rom_programmability_semantic_closed_form.
by [].
qed.

lemma ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_semantic :
  ms_rom_local_failure_mass <=
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic.
by [].
qed.