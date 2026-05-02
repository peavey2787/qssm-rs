require import AllCore List.
require import Algebra QssmTypes SchnorrBranch.
require import TrueClauseTypes TrueClauseMSB.

(* Semantic axiom, value-bit corollary, and MS_3b_true_clause_characterization chain. *)

axiom A_ms3b_operand_hdb_implies_msb_first_strict_gt :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms3b_msb_first_strict_gt_at vb tb p.

lemma A_ms3b_comparison_semantics :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    nth witness vb p = true.
proof.
move=> x vb tb p Hop Hhd.
have Hgt := A_ms3b_operand_hdb_implies_msb_first_strict_gt x vb tb p Hop Hhd.
case: Hgt=> _ [_ [Hvp _]].
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
have Hvp : nth witness vb p = true by exact (A_ms3b_comparison_semantics x vb tb p Hop Hhd).
have Hneq : nth witness vb p <> nth witness tb p by exact (A_ms3b_hdb_directionality vb tb p Hhd).
have Htn : nth witness tb p = false.
  have Hneq' := Hneq.
  rewrite Hvp in Hneq'.
  by case (nth witness tb p) Hneq'.
split; first exact Hvp.
exact Htn.
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
by move=> x vb tb p clause_pub r Hob; rewrite /ms3b_clause_opening_binds in Hob.
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
  (size vb = size tb /\ 0 < size vb) /\
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
  size vb = size tb /\ 0 < size vb =>
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
