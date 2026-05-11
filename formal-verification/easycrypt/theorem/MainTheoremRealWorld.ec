require import AllCore List.
require import StdOrder.
(*---*) import RealOrder.
require import QssmTypes SourceTypes Algebra FS SchnorrBranch TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonTheorem MS.
require import Simulator.
require import SourceDistributions SourceTheorem.
require BudgetParameters.
require import LESurface LEModel LERejectionSampler LEFsProgrammingSurface Games GameAdvantage GameMSHops GameMSHopComposition GameMSHopCompositionParameterized GameLEBridge GameLEBridgeParameterized.
require import LERejectionSamplerMassLiveParameterized LEFsProgrammingLiveParameterizedMass.
require import SourceHashBindingSemanticLiveParameterizedMass.
require import ComparisonPayloadSemanticLiveParameterizedMass.
require import MSProbabilitySurfaceRealWorld GameMSHopCompositionRealWorld GameLEBridgeRealWorld.
require import MainTheorem.
require import RealWorldBudgetParameters RealWorldBudgetObligations.

(* Parallel top-level real-world theorem companion.
   This keeps the frozen exact-zero and parameterized theorem surfaces unchanged
   while adding an abstract-budget theorem over the existing live lower masses. *)

lemma qssm_main_theorem_realworld_budget
  (b : realworld_budget) (x : qssm_public_input) (s : seed) (D : distinguisher) :
  qssm_realworld_obligations b
    (le_rejection_parameterized_failure_probability x s)
    LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
    (ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x))
    (ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x)) =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    epsilon_ms_hash_binding_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_le_realworld b.
proof.
move=> Hrw Hsetb Hleeqv.
pose xms := extract_ms_public x.
have Hrw_le :
    le_realworld_obligations b
      (le_rejection_parameterized_failure_probability x s)
      LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass.
  exact (qssm_realworld_obligations_le b
    (le_rejection_parameterized_failure_probability x s)
    LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
    (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
    (ms_rom_execution_owned_parameterized_failure_probability xms) Hrw).
have Hrw_ms :
    ms_realworld_obligations b
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms).
  exact (qssm_realworld_obligations_ms b
    (le_rejection_parameterized_failure_probability x s)
    LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
    (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
    (ms_rom_execution_owned_parameterized_failure_probability xms) Hrw).
have H01p : Adv_G0_G1_MS x xms s D <=
    epsilon_ms_hash_binding_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_ms_rom_programmability_realworld b.
  exact (A_G0_to_G1_ms_realworld_transition_bound b x xms s D Hrw_ms
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have Hmid : Adv_G1_MS_to_LE x xms s D <= 0%r.
  exact (A_G1_MS_to_LE_transition_bound x s D).
have H12rw : Adv_G1_G2_LE x xms s D <=
    epsilon_le_realworld b.
  exact (A_G1_to_G2_le_semantic_realworld_budget_transition_bound b x xms s D
    Hsetb A4_le_hvzk_bound_nonneg Hleeqv Hrw_le).
have Htri : Adv_G0_G2_QSSM x xms s D <=
  Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
have H01mid : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D <=
  (epsilon_ms_hash_binding_realworld b +
   epsilon_ms_rom_programmability_realworld b +
   epsilon_ms_rom_programmability_realworld b) + 0%r.
  by apply (ler_add _ _ _ _ H01p Hmid).
have Hadd : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D <=
  epsilon_ms_hash_binding_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_le_realworld b.
  have -> : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D =
    (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D by ring.
  have Hsum012mid :
      (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D <=
      ((epsilon_ms_hash_binding_realworld b +
        epsilon_ms_rom_programmability_realworld b +
        epsilon_ms_rom_programmability_realworld b) + 0%r) +
      epsilon_le_realworld b
    by apply (ler_add _ _ _ _ H01mid H12rw).
  apply (ler_trans _ _ _ Hsum012mid).
  have -> :
      ((epsilon_ms_hash_binding_realworld b +
        epsilon_ms_rom_programmability_realworld b +
        epsilon_ms_rom_programmability_realworld b) + 0%r) +
      epsilon_le_realworld b =
    epsilon_ms_hash_binding_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_ms_rom_programmability_realworld b +
    epsilon_le_realworld b by ring.
  by apply lerr.
by apply (ler_trans _ _ _ Htri Hadd).
qed.