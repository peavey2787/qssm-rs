require import AllCore List.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceDistributions SourceTheorem MS LEModel.
require import GameTypes GameViews GameAdvantage GameMSHopTypes GameMSHopTransitions.

(* G0→G1 MS hop: composed bound from MS1..MS3c segment obligations + telescope. *)
lemma A_G0_to_G1_ms_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    0%r <= epsilon_ms_rom_programmability =>
    ms3a_bitness_real_sim_equiv xms s =>
    (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
      ms3b_comparison_operand_bits xms vb tb =>
      ms_highest_differing_bit vb tb p =>
      ms_true_clause_position vb tb p =>
      ms3b_clause_opening_binds xms vb tb p clause_pub r =>
      ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    Adv_G0_G1_MS x xms s D <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability.
proof.
move=> x xms s D Hh Hr H3a H3b H3c.
have Htel := A_adv_ms_hop_telescope x xms s D.
rewrite /G_MS_real /G_MS_sim in Htel.
have [H1a [H1b [H1c [H1d [H1e H1f]]]]] := L_ms_MS1_stage_premises x xms s.
have [H2a [H2b [H2c [H2d [H2e H2f]]]]] := L_ms_MS2_stage_premises x xms s.
have [HS3arom [HS3abit [HS3ap1 [HS3ap2 [HS3aq1 HS3aq2]]]]] := L_ms_MS3a_stage_premises x xms s.
have [HS3bbit [HS3bcomp [HS3bp1 [HS3bp2 [HS3bq1 HS3bq2]]]]] := L_ms_MS3b_stage_premises x xms s.
have [HS3ccomp [HS3csim [HS3cp1 [HS3cp2 [HS3cq1 HS3cq2]]]]] := L_ms_MS3c_stage_premises x xms s.
have H1 := A_MS1_hash_binding_transition x xms s D Hh H1a H1b H1c H1d H1e H1f.
have H2 := A_MS2_rom_programming_transition x xms s D Hr H2a H2b H2c H2d H2e H2f.
have H3 := A_MS3a_bitness_transition x xms s D HS3arom HS3abit HS3ap1 HS3ap2 HS3aq1 HS3aq2 H3a.
have H4 := A_MS3b_true_clause_transition x xms s D HS3bbit HS3bcomp HS3bp1 HS3bp2 HS3bq1 HS3bq2 H3b.
have H5 := A_MS3c_comparison_transition x xms s D HS3ccomp HS3csim HS3cp1 HS3cp2 HS3cq1 HS3cq2 H3c.
rewrite /Adv_G0_G1_MS /G_MS_real /G_MS_sim.
rewrite Htel.
by smt().
qed.
