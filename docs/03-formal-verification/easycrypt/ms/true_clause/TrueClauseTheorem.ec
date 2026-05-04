require import AllCore List.
require import Algebra QssmTypes SchnorrBranch.
require import TrueClauseTypes TrueClauseMSB.

(* Semantic leaf: operands + HDB => value>target at p; MSB-first strict-greater is
   pure list geometry once the concrete comparison carrier fixes the operand
   slice and the true-clause opening. *)

lemma L_ms3b_int_lt1_eq0 (i : int) : 0 <= i => i < 1 => i = 0.
proof.
move=> Hi0 Hi1.
rewrite ltz1 in Hi1.
by rewrite eqz_leq; split=> //.
qed.

lemma A_ms3b_operand_hdb_implies_value_gt_target :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms3b_value_gt_target_at vb tb p.
proof.
move=> x vb tb p.
rewrite /ms3b_comparison_operand_bits /ms3b_phase1_comparison_carrier /=.
move=> [-> [-> [_ _]]] Hhd.
have Hwf := A_ms3b_hdb_implies_bitlists_wf [x.`mspi_result_bit] [false] p Hhd.
case: Hwf => _ [Hp0 Hplt].
have Hp : p = 0.
- apply (L_ms3b_int_lt1_eq0 p Hp0).
  by rewrite /= in Hplt.
have Hneq := A_ms3b_hdb_directionality [x.`mspi_result_bit] [false] p Hhd.
rewrite Hp /= in Hneq.
have Hbit : x.`mspi_result_bit = true by smt.
rewrite Hp Hbit /=.
by split.
qed.

lemma A_ms3b_operand_hdb_implies_msb_first_strict_gt :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms3b_msb_first_strict_gt_at vb tb p.
proof.
move=> x vb tb p Hop Hhd.
have Hvg := A_ms3b_operand_hdb_implies_value_gt_target x vb tb p Hop Hhd.
exact (L_ms3b_hdb_value_gt_target_implies_msb_first_strict_gt vb tb p Hhd Hvg).
qed.

lemma A_ms3b_comparison_semantics :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    nth witness vb p = true.
proof.
move=> x vb tb p Hop Hhd.
have [Hvp _] := A_ms3b_operand_hdb_implies_value_gt_target x vb tb p Hop Hhd.
exact Hvp.
qed.

lemma A_ms3b_hdb_implies_value_one_target_zero :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    nth witness vb p = true /\
    nth witness tb p = false.
proof.
move=> x vb tb p Hop Hhd.
exact (A_ms3b_operand_hdb_implies_value_gt_target x vb tb p Hop Hhd).
qed.

lemma A_ms3b_hdb_implies_true_clause_position (vb : bool list) (tb : bool list) (p : int) :
  ms_highest_differing_bit vb tb p =>
  nth witness vb p = true =>
  nth witness tb p = false =>
  ms_true_clause_position vb tb p.
proof.
move=> Hhd Hvp Htn.
rewrite /ms_true_clause_position.
split; first exact Hhd.
split; first exact Htn.
exact Hvp.
qed.

lemma A_ms3b_highest_differing_bit_correct :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms_true_clause_position vb tb p.
proof.
move=> x vb tb p Hop Hhd.
have [Hvp Htn] := A_ms3b_hdb_implies_value_one_target_zero x vb tb p Hop Hhd.
by apply (A_ms3b_hdb_implies_true_clause_position vb tb p Hhd Hvp Htn).
qed.

lemma A_ms3b_pedersen_opening_correct :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int)
    (clause_pub : sch_point) (r : scalar),
    ms3b_clause_opening_binds x vb tb p clause_pub r =>
    ms_clause_public_point_matches_blinder clause_pub true r.
proof.
by move=> x vb tb p clause_pub r [_ [_ [_ [_ [_ Hob]]]]].
qed.

lemma MS_3b_bits_from_public_input (x : ms_public_input) (vb : bool list) (tb : bool list) :
  ms3b_comparison_operand_bits x vb tb =>
  size vb = size tb /\
  0 < size vb.
proof.
by move=> Hop; apply (A_ms3b_bit_decomposition_correct x vb tb Hop).
qed.

lemma MS_3b_highest_diff_from_bits (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int) :
  ms3b_comparison_operand_bits x vb tb =>
  ms_highest_differing_bit vb tb p =>
  (size vb = size tb /\
  0 < size vb) /\
  ms_true_clause_position vb tb p.
proof.
move=> Hop Hhd.
have Hbits := MS_3b_bits_from_public_input x vb tb Hop.
split; first exact Hbits.
by apply (A_ms3b_highest_differing_bit_correct x vb tb p Hop Hhd).
qed.

lemma MS_3b_true_clause_from_highest_diff (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int) :
  ms3b_comparison_operand_bits x vb tb =>
  ms_highest_differing_bit vb tb p =>
  ms_true_clause_position vb tb p.
proof.
move=> Hop Hhd.
have [_ Htcp] := MS_3b_highest_diff_from_bits x vb tb p Hop Hhd.
by exact Htcp.
qed.

lemma MS_3b_clause_point_from_opening (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int)
  (clause_pub : sch_point) (r : scalar) :
  ms3b_comparison_operand_bits x vb tb =>
  size vb = size tb /\
  0 < size vb =>
  ms_true_clause_position vb tb p =>
  ms3b_clause_opening_binds x vb tb p clause_pub r =>
  ms_clause_public_point_matches_blinder clause_pub true r.
proof.
move=> Hop Hbits Hpos Hob.
have _ := Hop.
have _ := Hbits.
have _ := Hpos.
exact (A_ms3b_pedersen_opening_correct x vb tb p clause_pub r Hob).
qed.

lemma MS_3b_true_clause_characterization_from_highest_diff
  (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar) :
  ms3b_comparison_operand_bits x vb tb =>
  ms_highest_differing_bit vb tb p =>
  ms_true_clause_position vb tb p =>
  ms3b_clause_opening_binds x vb tb p clause_pub r =>
  ms_true_clause_points_are_blinder_points vb tb p clause_pub r.
proof.
move=> Hop Hhd Htcp Hob.
have Hbits := MS_3b_bits_from_public_input x vb tb Hop.
have Hgeom := MS_3b_highest_diff_from_bits x vb tb p Hop Hhd.
have Htcl := MS_3b_true_clause_from_highest_diff x vb tb p Hop Hhd.
have _ := Htcp.
have _ := Hgeom.
have _ := Htcl.
rewrite /ms_true_clause_points_are_blinder_points.
move=> Hpos.
exact (MS_3b_clause_point_from_opening x vb tb p clause_pub r Hop Hbits Hpos Hob).
qed.

lemma MS_3b_true_clause_characterization
  (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar) :
  ms3b_comparison_operand_bits x vb tb =>
  ms_highest_differing_bit vb tb p =>
  ms_true_clause_position vb tb p =>
  ms3b_clause_opening_binds x vb tb p clause_pub r =>
  ms_true_clause_points_are_blinder_points vb tb p clause_pub r.
proof.
move=> Hop Hhd Htcp Hob.
exact (MS_3b_true_clause_characterization_from_highest_diff x vb tb p clause_pub r Hop Hhd Htcp Hob).
qed.
