require import AllCore Real Ring StdOrder.

(*---*) import RealOrder.

require import QssmTypes.
require import SourceModel.
require import LESurface.
require import GameAdvantage.
require import GameMSHopCompositionRealWorld.
require import RealWorldBudgetParameters RealWorldBudgetObligations.
require import LERejectionConcreteReduction.
require import LERejectionSamplerParameterizedCore.
require import LERejectionSamplerMassLiveParameterized.
require import LEFsProgrammingLiveParameterizedMass.
require import SourceHashBindingSemanticLiveParameterizedMass.
require import ComparisonPayloadSemanticLiveParameterizedMass.
require import MainTheorem.
require import MainTheoremRealWorld.

(* Concrete external-bound instantiation skeleton.
   This packages a concrete real-world budget record and derives the existing
   real-world obligations from explicit component-bound premises only. *)

op lambda_concrete_128 : int = 128.

op q_concrete_128 : int = 2 ^ 20.

op n_concrete_128 : int = 2 ^ 10.

op r_concrete_128 : int = 1.

op epsilon_component_denominator_concrete_128 : int =
  316912650057057350374175801344.

op epsilon_component_concrete_128 : real =
  1%r / epsilon_component_denominator_concrete_128%r.

op epsilon_ms_hash_binding_concrete_128 : real =
  epsilon_component_concrete_128.

op epsilon_ms_rom_programmability_concrete_128 : real =
  epsilon_component_concrete_128.

op epsilon_le_rej_concrete_128 : real =
  epsilon_component_concrete_128.

op epsilon_le_fs_concrete_128 : real =
  epsilon_component_concrete_128.

op epsilon_le_concrete_128 : real =
  epsilon_le_rej_concrete_128 + epsilon_le_fs_concrete_128.

op realworld_budget_concrete_128 : realworld_budget =
  {| rwb_epsilon_ms_hash_binding = epsilon_ms_hash_binding_concrete_128;
     rwb_epsilon_ms_rom_programmability = epsilon_ms_rom_programmability_concrete_128;
     rwb_epsilon_le_rej = epsilon_le_rej_concrete_128;
     rwb_epsilon_le_fs = epsilon_le_fs_concrete_128 |}.

op epsilon_top_concrete_128 : real =
  epsilon_top_realworld realworld_budget_concrete_128.

pred le_rejection_concrete_128_reduction_obligation
  (x : qssm_public_input) (s : seed) =
  LERejectionConcreteReduction.le_rejection_concrete_reduction_obligation
    epsilon_le_rej_concrete_128 x s.

lemma epsilon_component_concrete_128_closed_form :
  epsilon_component_concrete_128 =
  1%r / epsilon_component_denominator_concrete_128%r.
proof. by rewrite /epsilon_component_concrete_128. qed.

lemma epsilon_component_concrete_128_nonneg :
  0%r <= epsilon_component_concrete_128.
proof.
rewrite epsilon_component_concrete_128_closed_form.
have Hden_pos : 0%r < epsilon_component_denominator_concrete_128%r.
  rewrite /epsilon_component_denominator_concrete_128.
  by smt().
by smt().
qed.

lemma epsilon_ms_hash_binding_concrete_128_nonneg :
  0%r <= epsilon_ms_hash_binding_concrete_128.
proof.
rewrite /epsilon_ms_hash_binding_concrete_128.
exact epsilon_component_concrete_128_nonneg.
qed.

lemma epsilon_ms_rom_programmability_concrete_128_nonneg :
  0%r <= epsilon_ms_rom_programmability_concrete_128.
proof.
rewrite /epsilon_ms_rom_programmability_concrete_128.
exact epsilon_component_concrete_128_nonneg.
qed.

lemma epsilon_le_rej_concrete_128_nonneg :
  0%r <= epsilon_le_rej_concrete_128.
proof.
rewrite /epsilon_le_rej_concrete_128.
exact epsilon_component_concrete_128_nonneg.
qed.

lemma epsilon_le_fs_concrete_128_nonneg :
  0%r <= epsilon_le_fs_concrete_128.
proof.
rewrite /epsilon_le_fs_concrete_128.
exact epsilon_component_concrete_128_nonneg.
qed.

lemma epsilon_le_concrete_128_nonneg :
  0%r <= epsilon_le_concrete_128.
proof.
rewrite /epsilon_le_concrete_128.
by smt(epsilon_le_rej_concrete_128_nonneg epsilon_le_fs_concrete_128_nonneg).
qed.

lemma realworld_budget_concrete_128_nonnegative :
  realworld_budget_nonnegative realworld_budget_concrete_128.
proof.
rewrite /realworld_budget_nonnegative /realworld_budget_concrete_128 /=.
split.
  exact epsilon_ms_hash_binding_concrete_128_nonneg.
split.
  exact epsilon_ms_rom_programmability_concrete_128_nonneg.
split.
  exact epsilon_le_rej_concrete_128_nonneg.
exact epsilon_le_fs_concrete_128_nonneg.
qed.

lemma epsilon_top_concrete_128_closed_form :
  epsilon_top_concrete_128 =
  epsilon_ms_hash_binding_concrete_128 +
  epsilon_ms_rom_programmability_concrete_128 +
  epsilon_ms_rom_programmability_concrete_128 +
  epsilon_le_concrete_128.
proof.
rewrite /epsilon_top_concrete_128.
rewrite (epsilon_top_realworld_component_sum realworld_budget_concrete_128).
rewrite (epsilon_le_realworld_component_sum realworld_budget_concrete_128).
by rewrite /realworld_budget_concrete_128 /= /epsilon_le_concrete_128.
qed.

lemma epsilon_top_concrete_128_eq_5_over_2_98 :
  epsilon_top_concrete_128 =
  5%r / epsilon_component_denominator_concrete_128%r.
proof.
rewrite epsilon_top_concrete_128_closed_form.
rewrite /epsilon_le_concrete_128.
rewrite /epsilon_ms_hash_binding_concrete_128.
rewrite /epsilon_ms_rom_programmability_concrete_128.
rewrite /epsilon_le_rej_concrete_128.
rewrite /epsilon_le_fs_concrete_128.
rewrite epsilon_component_concrete_128_closed_form.
by ring.
qed.

lemma qssm_realworld_obligations_concrete_128_from_component_bounds
  (epsilon_le_rej_actual epsilon_le_fs_actual
   epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  epsilon_le_rej_actual <= epsilon_le_rej_concrete_128 =>
  epsilon_le_fs_actual <= epsilon_le_fs_concrete_128 =>
  epsilon_ms_hash_binding_actual <= epsilon_ms_hash_binding_concrete_128 =>
  epsilon_ms_rom_actual <= epsilon_ms_rom_programmability_concrete_128 =>
  qssm_realworld_obligations realworld_budget_concrete_128
    epsilon_le_rej_actual epsilon_le_fs_actual
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual.
proof.
move=> Hlej Hlefs Hms1 Hms2.
rewrite /qssm_realworld_obligations /le_realworld_obligations /ms_realworld_obligations.
rewrite /realworld_budget_concrete_128 /=.
by split.
qed.

lemma ms_realworld_obligations_concrete_128_from_component_bounds
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  epsilon_ms_hash_binding_actual <= epsilon_ms_hash_binding_concrete_128 =>
  epsilon_ms_rom_actual <= epsilon_ms_rom_programmability_concrete_128 =>
  ms_realworld_obligations realworld_budget_concrete_128
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual.
proof.
move=> Hms1 Hms2.
rewrite /ms_realworld_obligations /realworld_budget_concrete_128 /=.
by split.
qed.

lemma qssm_main_theorem_realworld_concrete_128
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  le_rejection_parameterized_failure_probability x s <=
    epsilon_le_rej_concrete_128 =>
  LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass <=
    epsilon_le_fs_concrete_128 =>
  ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_hash_binding_concrete_128 =>
  ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_rom_programmability_concrete_128 =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    epsilon_ms_hash_binding_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_le_concrete_128.
proof.
move=> Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
have Hrw :
    qssm_realworld_obligations realworld_budget_concrete_128
      (le_rejection_parameterized_failure_probability x s)
      LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
      (ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x))
      (ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x)).
  exact (qssm_realworld_obligations_concrete_128_from_component_bounds
    (le_rejection_parameterized_failure_probability x s)
    LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass
    (ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x))
    (ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x))
    Hlej Hlefs Hms1 Hms2).
have Hmain := qssm_main_theorem_realworld_budget
  realworld_budget_concrete_128 x s D Hrw Hsetb Hleeqv.
rewrite -epsilon_top_concrete_128_closed_form.
rewrite /epsilon_top_concrete_128.
rewrite (epsilon_top_realworld_component_sum realworld_budget_concrete_128).
exact Hmain.
qed.

lemma qssm_main_theorem_realworld_concrete_128_5_over_2_98
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  le_rejection_parameterized_failure_probability x s <=
    epsilon_le_rej_concrete_128 =>
  LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass <=
    epsilon_le_fs_concrete_128 =>
  ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_hash_binding_concrete_128 =>
  ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_rom_programmability_concrete_128 =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    5%r / epsilon_component_denominator_concrete_128%r.
proof.
move=> Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
have Hmain := qssm_main_theorem_realworld_concrete_128 x s D
  Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
rewrite -epsilon_top_concrete_128_eq_5_over_2_98.
apply (ler_trans _ _ _ Hmain).
rewrite epsilon_top_concrete_128_closed_form.
by apply lerr.
qed.

lemma qssm_main_theorem_realworld_concrete_128_with_le_rejection_reduction
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  le_rejection_concrete_128_reduction_obligation x s =>
  LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass <=
    epsilon_le_fs_concrete_128 =>
  ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_hash_binding_concrete_128 =>
  ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_rom_programmability_concrete_128 =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    epsilon_ms_hash_binding_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_le_concrete_128.
proof.
move=> Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
pose xms := extract_ms_public x.
have Hrw_ms :
    ms_realworld_obligations realworld_budget_concrete_128
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms).
  exact (ms_realworld_obligations_concrete_128_from_component_bounds
    (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
    (ms_rom_execution_owned_parameterized_failure_probability xms)
    Hms1 Hms2).
have H01p : Adv_G0_G1_MS x xms s D <=
    epsilon_ms_hash_binding_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128.
  exact (A_G0_to_G1_ms_realworld_transition_bound realworld_budget_concrete_128
    x xms s D Hrw_ms
    (use_MS_3a xms s)
    (use_MS_3b xms)
    (use_MS_3c xms s)).
have Hmid : Adv_G1_MS_to_LE x xms s D <= 0%r.
  exact (A_G1_MS_to_LE_transition_bound x s D).
have H12rw : Adv_G1_G2_LE x xms s D <= epsilon_le_concrete_128.
  exact (A_G1_to_G2_le_concrete_reduction_transition_bound_from_obligation
    epsilon_le_rej_concrete_128 epsilon_le_fs_concrete_128 x xms s D Hlej Hlefs).
have Htri : Adv_G0_G2_QSSM x xms s D <=
  Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D.
  exact (A_adv_gamehop_triangle x xms s D).
have H01mid : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D <=
  (epsilon_ms_hash_binding_concrete_128 +
   epsilon_ms_rom_programmability_concrete_128 +
   epsilon_ms_rom_programmability_concrete_128) + 0%r.
  by apply (ler_add _ _ _ _ H01p Hmid).
have Hadd : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D <=
  epsilon_ms_hash_binding_concrete_128 +
  epsilon_ms_rom_programmability_concrete_128 +
  epsilon_ms_rom_programmability_concrete_128 +
  epsilon_le_concrete_128.
  have -> : Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D + Adv_G1_G2_LE x xms s D =
    (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D by ring.
  have Hsum012mid :
      (Adv_G0_G1_MS x xms s D + Adv_G1_MS_to_LE x xms s D) + Adv_G1_G2_LE x xms s D <=
      ((epsilon_ms_hash_binding_concrete_128 +
        epsilon_ms_rom_programmability_concrete_128 +
        epsilon_ms_rom_programmability_concrete_128) + 0%r) +
      epsilon_le_concrete_128
    by apply (ler_add _ _ _ _ H01mid H12rw).
  apply (ler_trans _ _ _ Hsum012mid).
  have -> :
      ((epsilon_ms_hash_binding_concrete_128 +
        epsilon_ms_rom_programmability_concrete_128 +
        epsilon_ms_rom_programmability_concrete_128) + 0%r) +
      epsilon_le_concrete_128 =
    epsilon_ms_hash_binding_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_ms_rom_programmability_concrete_128 +
    epsilon_le_concrete_128 by ring.
  by apply lerr.
by apply (ler_trans _ _ _ Htri Hadd).
qed.

lemma qssm_main_theorem_realworld_concrete_128_with_le_rejection_reduction_5_over_2_98
  (x : qssm_public_input) (s : seed) (D : distinguisher) :
  le_rejection_concrete_128_reduction_obligation x s =>
  LEFsProgrammingLiveParameterizedMass.le_fs_parameterized_local_bad_branch_mass <=
    epsilon_le_fs_concrete_128 =>
  ms_hash_binding_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_hash_binding_concrete_128 =>
  ms_rom_execution_owned_parameterized_failure_probability (extract_ms_public x) <=
    epsilon_ms_rom_programmability_concrete_128 =>
  set_b_parameter_well_formed =>
  le_real_sim_transcript_equiv x s =>
  Adv_G0_G2_QSSM x (extract_ms_public x) s D <=
    5%r / epsilon_component_denominator_concrete_128%r.
proof.
move=> Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
have Hmain := qssm_main_theorem_realworld_concrete_128_with_le_rejection_reduction
  x s D Hlej Hlefs Hms1 Hms2 Hsetb Hleeqv.
rewrite -epsilon_top_concrete_128_eq_5_over_2_98.
apply (ler_trans _ _ _ Hmain).
rewrite epsilon_top_concrete_128_closed_form.
by apply lerr.
qed.