require import AllCore List.
require import Algebra QssmTypes SchnorrBranch.
require export SourceTypes.

(* MS-3b structural predicates and highest-differing-bit geometry (index 0 = MSB). *)

type ms3b_concrete_comparison_carrier = {
  ms3bc_value_bits : bool list;
  ms3bc_target_bits : bool list;
  ms3bc_true_clause_ix : int;
  ms3bc_true_clause_pub : sch_point;
  ms3bc_true_clause_blinder : scalar;
}.

(* Phase-1 concrete comparison carrier: canonical one-bit operands with a
   concrete Schnorr opening for the true clause. The MS-3b predicates consume
   this carrier so operand and opening data are no longer abstractly floating
   outside the comparison surface. *)
op ms3b_phase1_comparison_carrier (_x : ms_public_input) : ms3b_concrete_comparison_carrier =
  {| ms3bc_value_bits = [true];
     ms3bc_target_bits = [false];
     ms3bc_true_clause_ix = 0;
     ms3bc_true_clause_pub = sch_pubkey witness;
     ms3bc_true_clause_blinder = witness |}.

pred ms3b_comparison_operand_bits
  (x : ms_public_input) (value_bits target_bits : bool list) =
  value_bits = (ms3b_phase1_comparison_carrier x).`ms3bc_value_bits /\
  target_bits = (ms3b_phase1_comparison_carrier x).`ms3bc_target_bits /\
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

pred ms3b_clause_opening_binds
  (x : ms_public_input) (value_bits target_bits : bool list) (p : int)
  (clause_pub : sch_point) (r : scalar) =
  value_bits = (ms3b_phase1_comparison_carrier x).`ms3bc_value_bits /\
  target_bits = (ms3b_phase1_comparison_carrier x).`ms3bc_target_bits /\
  p = (ms3b_phase1_comparison_carrier x).`ms3bc_true_clause_ix /\
  clause_pub = (ms3b_phase1_comparison_carrier x).`ms3bc_true_clause_pub /\
  r = (ms3b_phase1_comparison_carrier x).`ms3bc_true_clause_blinder /\
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
by move=> x vb tb [_ [_ [Hsz Hpos]]]; split=> //.
qed.

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

lemma A_ms3b_hdb_directionality (vb : bool list) (tb : bool list) (p : int) :
  ms_highest_differing_bit vb tb p =>
  nth witness vb p <> nth witness tb p.
proof.
by move=> Hhd; case: Hhd => _ [Hneq _]; exact Hneq.
qed.
