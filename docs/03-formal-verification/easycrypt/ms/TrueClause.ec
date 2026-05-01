require import AllCore List.
require import Algebra QssmTypes SchnorrBranch.

(* MS v2 comparison true-clause / highest-differing-bit characterization (MS-3b skeleton).
   Bit list convention: index 0 is the most significant bit; indices
   0 .. p-1 are "above" index p (more significant than the bit at p). *)

(* Structural well-formedness of comparison operands as boolean lists: same length,
   nonempty. Parameter `x : ms_public_input` is reserved for a future transcript /
   execution link (decode from observable / statement); there is no projection on
   `ms_public_input` in this skeleton. *)
pred ms3b_comparison_operand_bits
  (x : ms_public_input) (value_bits target_bits : bool list) =
  size value_bits = size target_bits /\
  0 < size value_bits.

pred ms_bitlists_wf_for_index (vb : bool list) (tb : bool list) (p : int) =
  size vb = size tb /\
  0 <= p /\
  p < size vb.

pred ms_bits_agree_more_significant (vb : bool list) (tb : bool list) (p : int) =
  forall (i : int), 0 <= i => i < p =>
    nth witness vb i = nth witness tb i.

pred ms_highest_differing_bit (value_bits target_bits : bool list) (p : int) =
  ms_bitlists_wf_for_index value_bits target_bits p /\
  nth witness value_bits p <> nth witness target_bits p /\
  ms_bits_agree_more_significant value_bits target_bits p.

pred ms_true_clause_position (value_bits target_bits : bool list) (p : int) =
  ms_highest_differing_bit value_bits target_bits p /\
  nth witness target_bits p = false /\
  nth witness value_bits p = true.

pred ms_clause_public_point_matches_blinder
  (commitment : sch_point) (expected_bit : bool) (blinder : scalar) =
  commitment = sch_pubkey blinder.

(* True-branch clause announcement is a Schnorr blinder point on generator H. *)
pred ms3b_clause_opening_binds
  (x : ms_public_input) (value_bits target_bits : bool list) (p : int)
  (clause_pub : sch_point) (r : scalar) =
  ms_clause_public_point_matches_blinder clause_pub true r.

pred ms_true_clause_points_are_blinder_points
  (value_bits target_bits : bool list) (p : int)
  (clause_pub : sch_point) (r : scalar) =
  ms_true_clause_position value_bits target_bits p =>
  ms_clause_public_point_matches_blinder clause_pub true r.

lemma A_ms3b_bit_decomposition_correct :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list),
    ms3b_comparison_operand_bits x vb tb =>
    size vb = size tb /\
    0 < size vb.
proof.
by move=> x vb tb [Hsz Hpos]; split=> //.
qed.

(* Decomposition of the former single MS-3b “highest differing ⇒ true clause” step.
   Agreement above index `p` is already packaged inside `ms_highest_differing_bit`. *)

lemma A_ms3b_hdb_implies_bits_above_equal (vb : bool list) (tb : bool list) (p : int) :
  ms_highest_differing_bit vb tb p =>
  ms_bits_agree_more_significant vb tb p.
proof.
by move=> Hhd; case: Hhd => _ [_ Hag]; exact Hag.
qed.

lemma A_ms3b_hdb_implies_bitlists_wf (vb : bool list) (tb : bool list) (p : int) :
  ms_highest_differing_bit vb tb p =>
  ms_bitlists_wf_for_index vb tb p.
proof.
by move=> Hhd; case: Hhd => Hwf _; exact Hwf.
qed.

(* Narrow residual: MS v2 / comparison protocol places the true clause on the branch
   with value_bit = true and target_bit = false at the highest-differing index. *)
axiom A_ms3b_hdb_implies_value_one_target_zero :
  forall (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int),
    ms3b_comparison_operand_bits x vb tb =>
    ms_highest_differing_bit vb tb p =>
    nth witness vb p = true /\
    nth witness tb p = false.

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
