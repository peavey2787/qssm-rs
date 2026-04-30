require import AllCore List.
require import QssmTypes Algebra FS SchnorrBranch TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonTheorem MS.
require import SourceDistributions SourceTheorem.
require import LEModel Games GameAdvantage GameMSHops GameMSHopComposition GameLEBridge.

axiom A1_ms_hash_binding :
  forall (D : distinguisher), 0%r <= epsilon_ms_hash_binding.

axiom A2_ms_rom_programmability :
  forall (D : distinguisher), 0%r <= epsilon_ms_rom_programmability.

axiom A4_le_hvzk :
  forall (D : distinguisher), 0%r <= epsilon_le.

(* Bridge to MS-3a/b/c placeholders (MS-3a via `ms/source/SourceTheorem.ec`). *)
lemma use_MS_3a (x : ms_public_input) (s : seed) : ms3a_bitness_real_sim_equiv x s.
proof.
by apply (MS_3a_exact_bitness_simulation x s).
qed.
lemma use_MS_3b (x : ms_public_input) (vb : bool list) (tb : bool list) (p : int)
  (clause_pub : sch_point) (r : scalar) :
  ms3b_comparison_operand_bits x vb tb =>
  ms_highest_differing_bit vb tb p =>
  ms_true_clause_position vb tb p =>
  ms3b_clause_opening_binds x vb tb p clause_pub r =>
  ms_true_clause_points_are_blinder_points vb tb p clause_pub r.
proof.
move=> Hop Hhd Htcp Hob.
exact (MS_3b_true_clause_characterization x vb tb p clause_pub r Hop Hhd Htcp Hob).
qed.
lemma use_MS_3c (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_comparison_global_programmable_under_A2 x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  ms_comparison_exact_simulation_equiv x s.
proof.
move=> Hann Ha2 Hfalse Htrue Hsum.
exact (MS_3c_exact_comparison_simulation x s Hann Ha2 Hfalse Htrue Hsum).
qed.

lemma qssm_main_theorem_skeleton
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) :
  ms3c_comparison_query_digest_ann_only xms s =>
  ms3c_comparison_global_programmable_under_A2 xms s =>
  ms3c_false_clauses_simulator_generated xms s =>
  ms3c_true_clause_schnorr_from_blinder xms s =>
  ms3c_clause_challenge_shares_sum xms s =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x xms s D <= Adv_G0_G1_MS x xms s D + Adv_G1_G2_LE x xms s D =>
  Adv_G0_G1_MS x xms s D <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability =>
  Adv_G1_G2_LE x xms s D <= epsilon_le =>
  Adv_G0_G2_QSSM x xms s D <=
    epsilon_ms_hash_binding +
    epsilon_ms_rom_programmability +
  epsilon_le.
proof.
move=> Hann Ha2 Hfalse Htrue Hsum Hsetb Hleeqv Hhop H01 H12.
have H01p : Adv_G0_G1_MS x xms s D <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability.
  exact (A_G0_to_G1_ms_transition_bound x xms s D
    (A1_ms_hash_binding D)
    (A2_ms_rom_programmability D)
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have H12p : Adv_G1_G2_LE x xms s D <= epsilon_le.
  exact (A_G1_to_G2_le_transition_bound x xms s D Hsetb (A4_le_hvzk D) Hleeqv).
have Htri : Adv_G0_G2_QSSM x xms s D <= Adv_G0_G1_MS x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
by smt().
qed.
