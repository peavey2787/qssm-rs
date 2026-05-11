require import AllCore List Distr.
require import StdOrder.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceTypes.
require import SourceDistributions SourceTheorem MS.
require import MSProbabilitySurface.
require import MSProbabilitySurfaceParameterized.
require import GameAdvantage.
require import GameViews.
require import GameMSHopTypes.
require import GameMSHopTransitions.
require import ComparisonPayloadSemanticLiveParameterizedCore.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticBridgeParameterized.
require import ComparisonPayloadSemanticLiveParameterizedMass.
require import MS1ConcreteReduction.
require import MS2ConcreteReduction.

(*---*) import RealOrder.

(* Parallel reduction-facing MS composition surface.
   This composes external MS1 and MS2 concrete reductions while preserving the
   duplicated MS2 landing. The original MS1-plus-live-premise theorem stays
   available as a sibling route. *)

lemma A_MS2_rom_programming_concrete_public_endpoint_transition_bound_from_obligation
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms2_concrete_reduction_obligation epsilon_ms_rom_bound xms =>
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D
    <= epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
have Hgap :
    `|ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state_parameterized xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_image_parameterizedE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_parameterized.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_live_parameterized.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state_parameterized xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
    (ms_after_rom_public_semantic_observable_of_state xms)
    (ms_rom_public_observable_divergence_condition xms) D).
  move=> st Hnodiv.
  have Hobs :=
    ms_after_rom_public_semantic_observable_of_state_no_divergenceE xms st Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D <=
    `|ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr
       (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D)).
have Hmass :=
  A_MS2_concrete_reduction_bound_from_obligation epsilon_ms_rom_bound xms Hms2.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_concrete_transition_bound_from_obligation
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms2_concrete_reduction_obligation epsilon_ms_rom_bound xms =>
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D
    <= epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
have Heq_canonical :
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D =
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D.
  apply (ms_view_distinguish_pr_respects_distribution_equality
    (d_ms_after_rom_observable_v2 x s xms)
    (d_ms_after_binding_observable_v2 x s xms) D).
  exact (d_ms_after_rom_observable_v2_eq_after_binding x s xms).
have Hgap :
    `|ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state_parameterized xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_image_parameterizedE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_parameterized.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_live_parameterized.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state_parameterized xms)
    (ms_after_rom_public_semantic_observable_of_state xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
    (ms_rom_public_observable_divergence_condition xms) D).
  move=> st Hnodiv.
  have Hobs :=
    ms_after_rom_public_semantic_observable_of_state_no_divergenceE xms st Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  A_MS2_concrete_reduction_bound_from_obligation epsilon_ms_rom_bound xms Hms2.
rewrite Heq_canonical.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma A_MS2_canonical_rom_programming_concrete_bound_from_obligation
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms2_concrete_reduction_obligation epsilon_ms_rom_bound xms =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <=
      epsilon_ms_rom_bound + epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
rewrite /Adv /game_pr /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
rewrite /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
have Hpublic :=
  A_MS2_rom_programming_concrete_public_endpoint_transition_bound_from_obligation
    epsilon_ms_rom_bound x s xms D Hms2.
have Hland :=
  A_MS_public_after_rom_to_canonical_after_rom_concrete_transition_bound_from_obligation
    epsilon_ms_rom_bound x s xms D Hms2.
have -> :
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D =
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
    (ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hpublic Hland).
qed.

lemma A_MS2_rom_programming_concrete_public_endpoint_transition_bound_from_premise
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_rom_execution_owned_parameterized_failure_probability xms <= epsilon_ms_rom_bound =>
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D
    <= epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_live_parameterized_failure x s xms D.
exact (ler_trans _ _ _ Hsemantic Hms2).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_concrete_transition_bound_from_premise
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_rom_execution_owned_parameterized_failure_probability xms <= epsilon_ms_rom_bound =>
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D
    <= epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
have Heq_canonical :
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D =
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D.
  apply (ms_view_distinguish_pr_respects_distribution_equality
    (d_ms_after_rom_observable_v2 x s xms)
    (d_ms_after_binding_observable_v2 x s xms) D).
  exact (d_ms_after_rom_observable_v2_eq_after_binding x s xms).
have Hgap :
    `|ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state_parameterized xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_image_parameterizedE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_parameterized.
  rewrite /d_ms_after_rom_public_semantic_observable_v2_live_parameterized.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state_parameterized xms)
    (ms_after_rom_public_semantic_observable_of_state xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
    (ms_rom_public_observable_divergence_condition xms) D).
  move=> st Hnodiv.
  have Hobs :=
    ms_after_rom_public_semantic_observable_of_state_no_divergenceE xms st Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  ms_rom_public_observable_divergence_mass_le_execution_owned_live_parameterized_failure xms.
rewrite Heq_canonical.
apply (ler_trans _ _ _ Hdir).
apply (ler_trans _ _ _ Hgap).
exact (ler_trans _ _ _ Hmass Hms2).
qed.

lemma A_MS2_canonical_rom_programming_concrete_bound_from_premise
  (epsilon_ms_rom_bound : real) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_rom_execution_owned_parameterized_failure_probability xms <= epsilon_ms_rom_bound =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <=
      epsilon_ms_rom_bound + epsilon_ms_rom_bound.
proof.
move=> x s xms D Hms2.
rewrite /Adv /game_pr /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
rewrite /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
have Hpublic :=
  A_MS2_rom_programming_concrete_public_endpoint_transition_bound_from_premise
    epsilon_ms_rom_bound x s xms D Hms2.
have Hland :=
  A_MS_public_after_rom_to_canonical_after_rom_concrete_transition_bound_from_premise
    epsilon_ms_rom_bound x s xms D Hms2.
have -> :
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D =
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
    (ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hpublic Hland).
qed.

lemma A_G0_to_G1_ms_concrete_reduction_transition_bound_from_ms1_obligation :
  forall (epsilon_ms1_bound epsilon_ms_rom_bound : real)
         (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    ms1_concrete_reduction_obligation epsilon_ms1_bound x s xms D =>
    ms_rom_execution_owned_parameterized_failure_probability xms <= epsilon_ms_rom_bound =>
    ms3a_bitness_real_sim_equiv xms s =>
    (forall (vb : bool list) (tb : bool list) (p : int)
            (clause_pub : sch_point) (r : scalar),
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
    Adv_G0_G1_MS x xms s D <=
      epsilon_ms1_bound + epsilon_ms_rom_bound + epsilon_ms_rom_bound.
proof.
move=> epsilon_ms1_bound epsilon_ms_rom_bound x xms s D Hms1 Hms2 H3a H3b H3c.
have Htel := A_adv_ms_hop_telescope x xms s D.
rewrite /G_MS_real /G_MS_sim in Htel.
have [H1a [H1b [H1c [H1d [H1e H1f]]]]] := L_ms_MS1_stage_premises x xms s.
have [H2a [H2b [H2c [H2d [H2e H2f]]]]] := L_ms_MS2_stage_premises x xms s.
have [HS3arom [HS3abit [HS3ap1 [HS3ap2 [HS3aq1 HS3aq2]]]]] := L_ms_MS3a_stage_premises x xms s.
have [HS3bbit [HS3bcomp [HS3bp1 [HS3bp2 [HS3bq1 HS3bq2]]]]] := L_ms_MS3b_stage_premises x xms s.
have [HS3ccomp [HS3csim [HS3cp1 [HS3cp2 [HS3cq1 HS3cq2]]]]] := L_ms_MS3c_stage_premises x xms s.
have H1 := A_MS1_concrete_reduction_bound_from_obligation
  epsilon_ms1_bound x s xms D Hms1.
have H2 := A_MS2_canonical_rom_programming_concrete_bound_from_premise
  epsilon_ms_rom_bound x s xms D Hms2.
have H3' := A_MS3a_bitness_transition x xms s D HS3arom HS3abit HS3ap1 HS3ap2 HS3aq1 HS3aq2 H3a.
have H4 := A_MS3b_true_clause_transition x xms s D HS3bbit HS3bcomp HS3bp1 HS3bp2 HS3bq1 HS3bq2 H3b.
have H5 := A_MS3c_comparison_transition x xms s D HS3ccomp HS3csim HS3cp1 HS3cp2 HS3cq1 HS3cq2 H3c.
rewrite /Adv_G0_G1_MS /G_MS_real /G_MS_sim.
rewrite Htel.
pose a1 := Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D.
pose a2 := Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D.
pose a3 := Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D.
pose a4 := Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D.
pose a5 := Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D.
have Ha34 : a3 + a4 + a5 <= 0%r.
  have Ha45 : a4 + a5 <= 0%r by apply (ler_add _ _ _ _ H4 H5).
  have Hsum : a3 + (a4 + a5) <= 0%r + 0%r by apply (ler_add _ _ _ _ H3' Ha45).
  have H01 : 0%r + 0%r <= 0%r.
    have ->: 0%r + 0%r = 0%r by ring.
    by apply lerr.
  have Ha34' : a3 + (a4 + a5) <= 0%r by apply (ler_trans _ _ _ Hsum H01).
  have ->: a3 + a4 + a5 = a3 + (a4 + a5) by ring.
  exact Ha34'.
have Ha12345 : a1 + a2 + a3 + a4 + a5 <= a1 + a2.
  have ->: a1 + a2 + a3 + a4 + a5 = (a1 + a2) + (a3 + a4 + a5) by ring.
  have Hstep : (a1 + a2) + (a3 + a4 + a5) <= (a1 + a2) + 0%r
    by apply (ler_add _ _ _ _ (lerr (a1 + a2)) Ha34).
  have Heq : (a1 + a2) + 0%r = a1 + a2 by ring.
  have Htail : (a1 + a2) + 0%r <= a1 + a2.
    rewrite Heq.
    by apply lerr.
  by apply (ler_trans _ _ _ Hstep Htail).
have Ha12 : a1 + a2 <=
    epsilon_ms1_bound + (epsilon_ms_rom_bound + epsilon_ms_rom_bound)
  by apply (ler_add _ _ _ _ H1 H2).
apply (ler_trans _ _ _ Ha12345).
apply (ler_trans _ _ _ Ha12).
have -> :
    epsilon_ms1_bound + (epsilon_ms_rom_bound + epsilon_ms_rom_bound) =
    epsilon_ms1_bound + epsilon_ms_rom_bound + epsilon_ms_rom_bound.
  by ring.
by apply lerr.
qed.

lemma A_G0_to_G1_ms_concrete_reduction_transition_bound_from_obligations :
  forall (epsilon_ms1_bound epsilon_ms_rom_bound : real)
         (x : qssm_public_input) (xms : ms_public_input) (s : seed)
         (D : distinguisher),
    ms1_concrete_reduction_obligation epsilon_ms1_bound x s xms D =>
    ms2_concrete_reduction_obligation epsilon_ms_rom_bound xms =>
    ms3a_bitness_real_sim_equiv xms s =>
    (forall (vb : bool list) (tb : bool list) (p : int)
            (clause_pub : sch_point) (r : scalar),
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
    Adv_G0_G1_MS x xms s D <=
      epsilon_ms1_bound + epsilon_ms_rom_bound + epsilon_ms_rom_bound.
proof.
move=> epsilon_ms1_bound epsilon_ms_rom_bound x xms s D Hms1 Hms2 H3a H3b H3c.
have Htel := A_adv_ms_hop_telescope x xms s D.
rewrite /G_MS_real /G_MS_sim in Htel.
have [H1a [H1b [H1c [H1d [H1e H1f]]]]] := L_ms_MS1_stage_premises x xms s.
have [H2a [H2b [H2c [H2d [H2e H2f]]]]] := L_ms_MS2_stage_premises x xms s.
have [HS3arom [HS3abit [HS3ap1 [HS3ap2 [HS3aq1 HS3aq2]]]]] := L_ms_MS3a_stage_premises x xms s.
have [HS3bbit [HS3bcomp [HS3bp1 [HS3bp2 [HS3bq1 HS3bq2]]]]] := L_ms_MS3b_stage_premises x xms s.
have [HS3ccomp [HS3csim [HS3cp1 [HS3cp2 [HS3cq1 HS3cq2]]]]] := L_ms_MS3c_stage_premises x xms s.
have H1 := A_MS1_concrete_reduction_bound_from_obligation
  epsilon_ms1_bound x s xms D Hms1.
have H2 := A_MS2_canonical_rom_programming_concrete_bound_from_obligation
  epsilon_ms_rom_bound x s xms D Hms2.
have H3' := A_MS3a_bitness_transition x xms s D HS3arom HS3abit HS3ap1 HS3ap2 HS3aq1 HS3aq2 H3a.
have H4 := A_MS3b_true_clause_transition x xms s D HS3bbit HS3bcomp HS3bp1 HS3bp2 HS3bq1 HS3bq2 H3b.
have H5 := A_MS3c_comparison_transition x xms s D HS3ccomp HS3csim HS3cp1 HS3cp2 HS3cq1 HS3cq2 H3c.
rewrite /Adv_G0_G1_MS /G_MS_real /G_MS_sim.
rewrite Htel.
pose a1 := Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D.
pose a2 := Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D.
pose a3 := Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D.
pose a4 := Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D.
pose a5 := Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D.
have Ha34 : a3 + a4 + a5 <= 0%r.
  have Ha45 : a4 + a5 <= 0%r by apply (ler_add _ _ _ _ H4 H5).
  have Hsum : a3 + (a4 + a5) <= 0%r + 0%r by apply (ler_add _ _ _ _ H3' Ha45).
  have H01 : 0%r + 0%r <= 0%r.
    have ->: 0%r + 0%r = 0%r by ring.
    by apply lerr.
  have Ha34' : a3 + (a4 + a5) <= 0%r by apply (ler_trans _ _ _ Hsum H01).
  have ->: a3 + a4 + a5 = a3 + (a4 + a5) by ring.
  exact Ha34'.
have Ha12345 : a1 + a2 + a3 + a4 + a5 <= a1 + a2.
  have ->: a1 + a2 + a3 + a4 + a5 = (a1 + a2) + (a3 + a4 + a5) by ring.
  have Hstep : (a1 + a2) + (a3 + a4 + a5) <= (a1 + a2) + 0%r
    by apply (ler_add _ _ _ _ (lerr (a1 + a2)) Ha34).
  have Heq : (a1 + a2) + 0%r = a1 + a2 by ring.
  have Htail : (a1 + a2) + 0%r <= a1 + a2.
    rewrite Heq.
    by apply lerr.
  by apply (ler_trans _ _ _ Hstep Htail).
have Ha12 : a1 + a2 <=
    epsilon_ms1_bound + (epsilon_ms_rom_bound + epsilon_ms_rom_bound)
  by apply (ler_add _ _ _ _ H1 H2).
apply (ler_trans _ _ _ Ha12345).
apply (ler_trans _ _ _ Ha12).
have -> :
    epsilon_ms1_bound + (epsilon_ms_rom_bound + epsilon_ms_rom_bound) =
    epsilon_ms1_bound + epsilon_ms_rom_bound + epsilon_ms_rom_bound.
  by ring.
by apply lerr.
qed.