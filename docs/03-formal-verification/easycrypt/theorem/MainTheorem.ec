require import AllCore List.
require import StdOrder.
(*---*) import RealOrder.
require import QssmTypes SourceTypes Algebra FS SchnorrBranch TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem MS.
require import Simulator.
require import SourceDistributions SourceTheorem.
require import LESurface LEModel Games GameAdvantage GameMSHops GameMSHopComposition GameLEBridge.

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
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    epsilon_ms_hash_binding +
    epsilon_ms_rom_programmability +
  epsilon_le.
proof.
move=> Hsetb Hleeqv.
pose xms := extract_ms_public x.
have H01p : Adv_G0_G1_MS x xms s D <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability.
  exact (A_G0_to_G1_ms_transition_bound x xms s D
    A1_ms_hash_binding_nonneg
    A2_ms_rom_programmability_nonneg
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have Hmid : Adv_G1_MS_to_LE x xms s D <= 0%r.
  exact (A_G1_MS_to_LE_transition_bound x s D).
have H12p : Adv_G1_G2_LE x xms s D <= epsilon_le.
  exact (A_G1_to_G2_le_transition_bound x xms s D Hsetb A4_le_hvzk_bound_nonneg Hleeqv).
have Htri : Adv_G0_G2_QSSM x xms s D <=
  Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
have H01mid : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D <=
  (epsilon_ms_hash_binding + epsilon_ms_rom_programmability) + 0%r.
  by apply (ler_add _ _ _ _ H01p Hmid).
have Hadd : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D <=
  epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le.
  have ->: Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D =
    (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D by ring.
  have Hsum012 :
      (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D <=
      ((epsilon_ms_hash_binding + epsilon_ms_rom_programmability) + 0%r) + epsilon_le
    by apply (ler_add _ _ _ _ H01mid H12p).
  have ->: ((epsilon_ms_hash_binding + epsilon_ms_rom_programmability) + 0%r) + epsilon_le =
    epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le by ring.
  exact Hsum012.
by apply (ler_trans _ _ _ Htri Hadd).
qed.

(* Concrete zero-budget corollary.

   With `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, and
   `epsilon_le` all defined as `0%r` in `primitives/BudgetParameters.ec`
   (justified by exact distribution / sdist equalities at every transition in
   the current model), the additive bound collapses to `<= 0%r`. This is the
   exact-zero gap of the current model, NOT a nonzero cryptographic security
   bound. *)
lemma qssm_main_theorem
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <= 0%r.
proof.
move=> Hsetb Hleeqv.
have Hskel := qssm_main_theorem_skeleton x s D Hsetb Hleeqv.
have Heq :
  epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le = 0%r.
- rewrite /epsilon_ms_hash_binding /epsilon_ms_rom_programmability /epsilon_le.
  by ring.
by rewrite -Heq.
qed.
