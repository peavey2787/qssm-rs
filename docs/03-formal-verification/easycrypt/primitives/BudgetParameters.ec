require import AllCore Distr List IntDiv.

import Ring.IntID StdOrder.IntOrder Range.

(* Concrete zero-budget model.

   At the current abstraction level every transition that these budgets bound
   is already proved by an exact distribution / statistical-distance equality:

   - MS1 hash-binding: `L_ms1_hash_binding_stage_zero` proves the Real and
     AfterBinding observable distributions are equal.
   - MS2 ROM-programming: `L_ms2_rom_programming_transition_zero` proves the
     AfterBinding and AfterRom observable distributions are equal.
   - Shadow LE rejection component: `epsilon_le_rej` is installed as the
     future lower rejection budget, but it is intentionally kept at `0%r`
     until the shadow rejection lane is wired into the active LE theorem path.
   - Shadow LE FS component: `epsilon_le_fs` is still `0%r`, but now for a
     semantic reason rather than only as a placeholder. The active
     branch-sensitive shadow lane measures failure by the shadow bad-branch
     condition on the post-constructor state, and that event is still proved
     impossible on the current concrete support because
     `d_le_pre_fs_programming_view x s` remains a `dunit` push-forward of
     `le_real_execution_observable x s` and the concrete real query material
     fixes `leqm_bad_flag = false`.
   - LE HVZK umbrella budget: `epsilon_le` is now defined as the sum of the
     lower component budgets `epsilon_le_rej + epsilon_le_fs`. In the current
     model both component lanes are still exact-zero, so the LE real and sim
     view distributions coincide and the umbrella bound is also identically 0.

  Therefore each active exact-zero budget is defined as `0%r`. This is NOT a
  nonzero cryptographic security bound; it records the exact-zero gap of the
  current model. Parallel semantic-owned LE budgets may coexist beside that
  exact-zero route without changing it. Any future refinement that introduces a
  non-identity rejection sampler, a genuinely supported FS bad branch, or a
  quantitative ROM model on the active route must restore a nonzero budget
  formula here. *)

op epsilon_ms_hash_binding : real = 0%r.

lemma A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.
proof. by rewrite /epsilon_ms_hash_binding. qed.

op epsilon_ms_rom_programmability : real = 0%r.

lemma A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.
proof. by rewrite /epsilon_ms_rom_programmability. qed.

op epsilon_le_rej : real = 0%r.

lemma A4_le_rejection_nonneg :
  0%r <= epsilon_le_rej.
proof. by rewrite /epsilon_le_rej. qed.

op epsilon_le_fs : real = 0%r.

lemma A4_le_fs_nonneg :
  0%r <= epsilon_le_fs.
proof. by rewrite /epsilon_le_fs. qed.

op total_slot_count : int = 4.

op bad_slot_count : int = 2.

lemma total_slot_count_pos :
  0 < total_slot_count.
proof. by rewrite /total_slot_count. qed.

lemma bad_slot_count_pos :
  0 < bad_slot_count.
proof. by rewrite /bad_slot_count. qed.

lemma bad_slot_count_lt_total_slot_count :
  bad_slot_count < total_slot_count.
proof. by rewrite /bad_slot_count /total_slot_count. qed.

op le_fs_semantic_branch_slot_support : int list = range 0 total_slot_count.

lemma le_fs_semantic_branch_slot_supportE :
  le_fs_semantic_branch_slot_support = [0; 1; 2; 3].
proof.
rewrite /le_fs_semantic_branch_slot_support /total_slot_count.
rewrite (range_ltn 0 4) 1:/# /=.
rewrite (range_ltn 1 4) 1:/# /=.
rewrite (range_ltn 2 4) 1:/# /=.
rewrite (range_ltn 3 4) 1:/# /=.
by rewrite range_geq /=.
qed.

lemma le_fs_semantic_branch_slot_support_uniq :
  uniq le_fs_semantic_branch_slot_support.
proof. by rewrite /le_fs_semantic_branch_slot_support range_uniq. qed.

op le_fs_semantic_bad_branch_slot (slot : int) : bool =
  slot < bad_slot_count.

op d_le_fs_semantic_branch_slot_choice : int distr =
  duniform le_fs_semantic_branch_slot_support.

lemma le_fs_semantic_branch_slot_choice_lossless :
  is_lossless d_le_fs_semantic_branch_slot_choice.
proof.
rewrite /d_le_fs_semantic_branch_slot_choice /le_fs_semantic_branch_slot_support.
by apply duniform_ll; rewrite range_ltn /total_slot_count.
qed.

op le_fs_semantic_branch_support : bool list = [false; true].

lemma le_fs_semantic_branch_support_uniq :
  uniq le_fs_semantic_branch_support.
proof. by rewrite /le_fs_semantic_branch_support. qed.

op d_le_fs_semantic_branch_choice : bool distr =
  dmap d_le_fs_semantic_branch_slot_choice le_fs_semantic_bad_branch_slot.

lemma le_fs_semantic_branch_choice_lossless :
  is_lossless d_le_fs_semantic_branch_choice.
proof.
rewrite /d_le_fs_semantic_branch_choice.
by apply dmap_ll; exact le_fs_semantic_branch_slot_choice_lossless.
qed.

lemma le_fs_semantic_good_branch_has_support :
  false \in d_le_fs_semantic_branch_choice.
proof.
rewrite /d_le_fs_semantic_branch_choice.
apply/supp_dmap.
exists bad_slot_count; split.
  rewrite /d_le_fs_semantic_branch_slot_choice /le_fs_semantic_branch_slot_support.
  rewrite supp_duniform mem_range.
  by split; first smt(bad_slot_count_pos); smt(bad_slot_count_lt_total_slot_count).
by rewrite /le_fs_semantic_bad_branch_slot ltrr.
qed.

lemma le_fs_semantic_bad_branch_has_support :
  true \in d_le_fs_semantic_branch_choice.
proof.
rewrite /d_le_fs_semantic_branch_choice.
apply/supp_dmap.
exists 0; split.
  rewrite /d_le_fs_semantic_branch_slot_choice /le_fs_semantic_branch_slot_support.
  by rewrite supp_duniform mem_range /total_slot_count.
by rewrite /le_fs_semantic_bad_branch_slot /bad_slot_count.
qed.

lemma le_fs_semantic_branch_choice_mass_false :
  mu1 d_le_fs_semantic_branch_choice false =
  (total_slot_count - bad_slot_count)%r / total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 false \o le_fs_semantic_bad_branch_slot)
      le_fs_semantic_branch_slot_support = 2.
  by rewrite le_fs_semantic_branch_slot_supportE /le_fs_semantic_bad_branch_slot
             /bad_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
have -> : (total_slot_count - bad_slot_count)%r / total_slot_count%r = 1%r / 2%r.
  by rewrite /total_slot_count /bad_slot_count /=.
by smt().
qed.

lemma le_fs_semantic_branch_choice_mass_true :
  mu1 d_le_fs_semantic_branch_choice true =
  bad_slot_count%r / total_slot_count%r.
proof.
rewrite /mu1 /d_le_fs_semantic_branch_choice dmapE /=.
rewrite /d_le_fs_semantic_branch_slot_choice duniformE.
rewrite undup_id ?le_fs_semantic_branch_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o le_fs_semantic_bad_branch_slot)
      le_fs_semantic_branch_slot_support = 2.
  by rewrite le_fs_semantic_branch_slot_supportE /le_fs_semantic_bad_branch_slot
             /bad_slot_count /pred1 /(\o) /=.
rewrite Hcount le_fs_semantic_branch_slot_supportE /=.
have -> : bad_slot_count%r / total_slot_count%r = 1%r / 2%r.
  by rewrite /total_slot_count /bad_slot_count /=.
by smt().
qed.

op epsilon_le_fs_semantic : real = mu1 d_le_fs_semantic_branch_choice true.

lemma epsilon_le_fs_semantic_closed_form :
  epsilon_le_fs_semantic = bad_slot_count%r / total_slot_count%r.
proof.
rewrite /epsilon_le_fs_semantic.
exact le_fs_semantic_branch_choice_mass_true.
qed.

lemma A4_le_fs_semantic_nonneg :
  0%r <= epsilon_le_fs_semantic.
proof.
rewrite epsilon_le_fs_semantic_closed_form.
by smt().
qed.

op epsilon_le_semantic : real = epsilon_le_rej + epsilon_le_fs_semantic.

lemma epsilon_le_semantic_component_sum :
  epsilon_le_semantic = epsilon_le_rej + epsilon_le_fs_semantic.
proof. by rewrite /epsilon_le_semantic. qed.

lemma epsilon_le_semantic_nonneg :
  0%r <= epsilon_le_semantic.
proof.
rewrite /epsilon_le_semantic /epsilon_le_rej /epsilon_le_fs_semantic.
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