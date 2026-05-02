require import AllCore List.
require import Algebra QssmTypes SchnorrBranch.
require import TrueClauseTypes.

(* MSB-first strict-greater bit pattern at first differing index + equivalences. *)

(* Value branch beats target at p (execution comparison direction); geometric
   agreement/disagreement above p is still carried by `ms_highest_differing_bit`. *)
pred ms3b_value_gt_target_at (value_bits target_bits : bool list) (p : int) =
  nth witness value_bits p = true /\
  nth witness target_bits p = false.

pred ms3b_msb_first_strict_gt_at (value_bits target_bits : bool list) (p : int) =
  ms_bitlists_wf_for_index value_bits target_bits p /\
  ms_bits_agree_more_significant value_bits target_bits p /\
  nth witness value_bits p = true /\
  nth witness target_bits p = false.

lemma L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt
  (vb tb : bool list) (p : int) :
  ms_highest_differing_bit vb tb p =>
  ms3b_value_gt_target_at vb tb p =>
  ms3b_msb_first_strict_gt_at vb tb p.
proof.
move=> Hhd [Hvp Htn].
case: Hhd => Hwf [_ Hag].
rewrite /ms3b_msb_first_strict_gt_at.
split; first exact Hwf.
split; first exact Hag.
split; first exact Hvp.
exact Htn.
qed.

lemma L_ms3b_msb_first_strict_gt_at_implies_hdb (vb tb : bool list) (p : int) :
  ms3b_msb_first_strict_gt_at vb tb p =>
  ms_highest_differing_bit vb tb p.
proof.
move=> Hgt.
case: Hgt => Hwf [Hag [Hvp Htn]].
split; first exact Hwf.
split; first by rewrite Hvp Htn.
exact Hag.
qed.

lemma L_ms3b_tcp_iff_msb_first_strict_gt (vb tb : bool list) (p : int) :
  ms_true_clause_position vb tb p <=> ms3b_msb_first_strict_gt_at vb tb p.
proof.
rewrite /ms_true_clause_position /ms3b_msb_first_strict_gt_at /ms_highest_differing_bit.
split.
  move=> [Hhd [Htn Hvp]].
  case: Hhd => Hwf [_ Hag].
  by split=> //; split=> //; split=> //.
move=> [Hwf [Hag [Hvp Htn]]].
split; last by split.
split; first exact Hwf.
split; first by rewrite Hvp Htn.
exact Hag.
qed.
