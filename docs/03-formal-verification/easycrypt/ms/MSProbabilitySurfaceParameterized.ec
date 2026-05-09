require import AllCore List Distr.
require import SDist.
require import StdOrder.
require import QssmTypes Algebra.
require import FS.
require import TranscriptObservable.
require import MS.
require import SourceTypes SourceModel.
require import MSProbabilitySurface.
require import SourceHashBindingSemanticBridgeParameterized.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticBridgeParameterized.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Parallel parameterized MS probability surface.
   This file leaves the existing demo semantic route untouched and lifts the
   theorem-facing public-endpoint surface onto the parameterized MS1/MS2 bridge
   companions. The staged public-endpoint route stays above this layer. *)

lemma A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
have Hdemo :=
  A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound x s xms D.
rewrite /MS.epsilon_ms_hash_binding_semantic in Hdemo.
rewrite -epsilon_ms_hash_binding_semantic_eq_epsilon_ms_hash_binding_parameterized.
exact Hdemo.
qed.

lemma A_MS2_rom_programming_parameterized_public_endpoint_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_semantic_failure x s xms D.
have Hbridge :=
  A_MS2_rom_programming_execution_owned_parameterized_bound xms.
exact (ler_trans _ _ _ Hsemantic Hbridge).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
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
        (d_ms_after_rom_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_imageE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state xms)
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
      (d_ms_after_rom_public_semantic_observable_v2 x s xms) D -
    ms_view_distinguish_pr
      (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr
        (d_ms_after_rom_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr
        (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr
       (d_ms_after_rom_public_semantic_observable_v2 x s xms) D -
     ms_view_distinguish_pr
       (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure xms.
have Hbridge :=
  A_MS2_rom_programming_execution_owned_parameterized_bound xms.
rewrite Heq_canonical.
apply (ler_trans _ _ _ Hdir).
apply (ler_trans _ _ _ Hgap).
exact (ler_trans _ _ _ Hmass Hbridge).
qed.

lemma A_MS_public_endpoint_parameterized_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized +
     ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hms1 :=
  A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound x s xms D.
have Hms2 :=
  A_MS2_rom_programming_parameterized_public_endpoint_transition_bound x s xms D.
have -> :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D =
  (ms_view_distinguish_pr
     (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
   ms_view_distinguish_pr
     (d_ms_after_binding_observable_v2 x s xms) D) +
  (ms_view_distinguish_pr
     (d_ms_after_binding_observable_v2 x s xms) D -
   ms_view_distinguish_pr
     (d_ms_after_rom_public_semantic_observable_v2 x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hms1 Hms2).
qed.