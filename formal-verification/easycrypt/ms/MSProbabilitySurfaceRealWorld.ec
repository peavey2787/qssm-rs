require import AllCore List Distr.
require import SDist.
require import StdOrder.
require import QssmTypes Algebra.
require import FS.
require import TranscriptObservable.
require import MS.
require import SourceTypes SourceModel.
require import SourceBitnessDistributions.
require import SourceObservableDistributions.
require import SourceHashBindingSemanticLiveParameterizedMass.
require import SourceHashBindingSemanticBridgeParameterized.
require import ComparisonPayloadSemanticLiveParameterizedCore.
require import ComparisonPayloadSemanticLiveParameterizedMass.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticBridgeParameterized.
require import MSProbabilitySurface.
require import MSProbabilitySurfaceParameterized.
require import RealWorldBudgetParameters RealWorldBudgetObligations.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Parallel real-world MS probability surface.
   This reuses the existing live parameterized execution-owned failure masses as
   lower obligations and threads them through an abstract real-world budget
   bundle without changing the routed parameterized theorem surface. *)

lemma A_MS1_hash_binding_realworld_bad_event_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_realworld_obligations b
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms) =>
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D -
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D
    <= epsilon_ms_hash_binding_realworld b.
proof.
move=> x s xms D Hrw.
have Hms1_actual_nonneg :
    0%r <= ms_hash_binding_execution_owned_parameterized_failure_probability xms.
  rewrite ms_hash_binding_execution_owned_parameterized_failure_probability_eq_epsilon_ms_hash_binding_parameterized.
  exact ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized_nonneg.
have Hbudget_nonneg : 0%r <= epsilon_ms_hash_binding_realworld b.
  exact (ms_realworld_obligations_ms1_budget_nonneg b
    (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
    (ms_rom_execution_owned_parameterized_failure_probability xms)
    Hms1_actual_nonneg Hrw).
have -> :
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
  exact (L_ms1_hash_binding_stage_zero x s xms D).
have -> :
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D = 0%r.
  by ring.
exact Hbudget_nonneg.
qed.

lemma A_MS2_rom_programming_realworld_public_endpoint_transition_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_realworld_obligations b
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms) =>
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D
    <= epsilon_ms_rom_programmability_realworld b.
proof.
move=> x s xms D Hrw.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_live_parameterized_failure x s xms D.
have Hbudget := ms_realworld_obligations_ms2_bound b
  (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
  (ms_rom_execution_owned_parameterized_failure_probability xms) Hrw.
exact (ler_trans _ _ _ Hsemantic Hbudget).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_realworld_transition_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_realworld_obligations b
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms) =>
    ms_view_distinguish_pr
      (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D
    <= epsilon_ms_rom_programmability_realworld b.
proof.
move=> x s xms D Hrw.
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
have Hbudget := ms_realworld_obligations_ms2_bound b
  (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
  (ms_rom_execution_owned_parameterized_failure_probability xms) Hrw.
rewrite Heq_canonical.
apply (ler_trans _ _ _ Hdir).
apply (ler_trans _ _ _ Hgap).
exact (ler_trans _ _ _ Hmass Hbudget).
qed.

lemma A_MS2_canonical_rom_programming_realworld_bound
  (b : realworld_budget) :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_realworld_obligations b
      (ms_hash_binding_execution_owned_parameterized_failure_probability xms)
      (ms_rom_execution_owned_parameterized_failure_probability xms) =>
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D
    <= epsilon_ms_rom_programmability_realworld b +
       epsilon_ms_rom_programmability_realworld b.
proof.
move=> x s xms D Hrw.
have Hpublic :=
  A_MS2_rom_programming_realworld_public_endpoint_transition_bound b x s xms D Hrw.
have Hland :=
  A_MS_public_after_rom_to_canonical_after_rom_realworld_transition_bound b x s xms D Hrw.
have -> :
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_observable_v2 x s xms) D =
    (ms_view_distinguish_pr
       (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
    (ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_rom_observable_v2 x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hpublic Hland).
qed.