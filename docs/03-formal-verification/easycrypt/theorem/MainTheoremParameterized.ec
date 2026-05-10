require import AllCore List.
require import StdOrder.
(*---*) import RealOrder.
require import QssmTypes SourceTypes Algebra FS SchnorrBranch TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem MS.
require import Simulator.
require import SourceDistributions SourceTheorem.
require BudgetParameters.
require import LESurface LEModel LERejectionSampler LEFsProgrammingSurface Games GameAdvantage GameMSHops GameMSHopComposition GameMSHopCompositionParameterized GameLEBridge GameLEBridgeParameterized.
require import MainTheorem.
require ParameterizedBudgetParameters.

(* Parallel top-level parameterized theorem companions.
  The LE-only theorem is preserved for the earlier narrow route. The full
  canonical parameterized theorem now closes through the canonical MS route
  with an explicit duplicated MS2 landing charge. *)

lemma qssm_main_theorem_le_parameterized_budget
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    MS.epsilon_ms_hash_binding_semantic +
    epsilon_ms_rom_programmability_semantic +
    ParameterizedBudgetParameters.epsilon_le_parameterized.
proof.
move=> Hsetb Hleeqv.
pose xms := extract_ms_public x.
have H01p : Adv_G0_G1_MS x xms s D <=
    MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic.
  exact (A_G0_to_G1_ms_semantic_transition_bound x xms s D
    MS.A1_ms_hash_binding_semantic_nonneg
    A2_ms_rom_programmability_semantic_nonneg
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have Hmid : Adv_G1_MS_to_LE x xms s D <= 0%r.
  exact (A_G1_MS_to_LE_transition_bound x s D).
have H12param : Adv_G1_G2_LE x xms s D <=
    ParameterizedBudgetParameters.epsilon_le_parameterized.
  exact (A_G1_to_G2_le_semantic_parameterized_budget_transition_bound x xms s D
    Hsetb A4_le_hvzk_bound_nonneg Hleeqv).
have Htri : Adv_G0_G2_QSSM x xms s D <=
  Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
have H01mid : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D <=
  (MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic) + 0%r.
  by apply (ler_add _ _ _ _ H01p Hmid).
have Hadd : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D <=
  MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic +
  ParameterizedBudgetParameters.epsilon_le_parameterized.
  have ->: Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D =
    (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D by ring.
  have Hsum012mid :
      (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D <=
      ((MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic) + 0%r) +
      ParameterizedBudgetParameters.epsilon_le_parameterized
    by apply (ler_add _ _ _ _ H01mid H12param).
  apply (ler_trans _ _ _ Hsum012mid).
  have -> : ((MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic) + 0%r) +
      ParameterizedBudgetParameters.epsilon_le_parameterized =
    MS.epsilon_ms_hash_binding_semantic + epsilon_ms_rom_programmability_semantic +
    ParameterizedBudgetParameters.epsilon_le_parameterized by ring.
  by apply lerr.
by apply (ler_trans _ _ _ Htri Hadd).
qed.

lemma qssm_main_theorem_parameterized_budget
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_le_parameterized.
proof.
move=> Hsetb Hleeqv.
pose xms := extract_ms_public x.
have H01p : Adv_G0_G1_MS x xms s D <=
    ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
  exact (A_G0_to_G1_ms_parameterized_transition_bound x xms s D
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have Hmid : Adv_G1_MS_to_LE x xms s D <= 0%r.
  exact (A_G1_MS_to_LE_transition_bound x s D).
have H12param : Adv_G1_G2_LE x xms s D <=
    ParameterizedBudgetParameters.epsilon_le_parameterized.
  exact (A_G1_to_G2_le_semantic_parameterized_budget_transition_bound x xms s D
    Hsetb A4_le_hvzk_bound_nonneg Hleeqv).
have Htri : Adv_G0_G2_QSSM x xms s D <=
  Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
have H01mid : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D <=
  (ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
   ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
   ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized) + 0%r.
  by apply (ler_add _ _ _ _ H01p Hmid).
have Hadd : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D <=
  ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
  ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
  ParameterizedBudgetParameters.epsilon_le_parameterized.
  have -> : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D =
    (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D by ring.
  have Hsum012mid :
      (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D <=
      ((ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
        ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
        ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized) + 0%r) +
      ParameterizedBudgetParameters.epsilon_le_parameterized
    by apply (ler_add _ _ _ _ H01mid H12param).
  apply (ler_trans _ _ _ Hsum012mid).
  have -> :
      ((ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
        ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
        ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized) + 0%r) +
      ParameterizedBudgetParameters.epsilon_le_parameterized =
    ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_le_parameterized by ring.
  by apply lerr.
by apply (ler_trans _ _ _ Htri Hadd).
qed.