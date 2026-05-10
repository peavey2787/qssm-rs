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
require import SourceHashBindingSemanticBridge.
require import MSProbabilitySurface.
require import ComparisonCouplingMarginals.
require import SourceHashBindingSemanticBridgeParameterized.
require import SourceHashBindingSemanticSlotMassParameterized.
require import SourceHashBindingSemanticLiveParameterizedCore.
require import ComparisonPayloadSemanticLiveParameterizedCore.
require import ComparisonPayloadSemanticLiveParameterizedMass.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticBridgeParameterized.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Parallel parameterized MS probability surface.
  This now routes both MS1 and MS2 through live parameterized lower lanes
  while leaving the demo semantic and exact-zero routes untouched. *)

op d_ms_after_binding_public_semantic_observable_v2_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  d_ms_hash_binding_public_semantic_observable_v2_parameterized xms.

op d_ms_after_rom_public_semantic_observable_v2_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  d_ms_after_rom_public_semantic_observable_v2_live_parameterized xms.

lemma A_MS1_hash_binding_parameterized_bad_event_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D
  <= ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
have Heq := L_ms1_hash_binding_stage_zero x s xms D.
have Hbridge := A_MS1_hash_binding_execution_owned_parameterized_bound xms.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
  exact Heq.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D = 0%r.
  by ring.
exact ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized_nonneg.
qed.

lemma A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D
  <= ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
have Hcategory_ll :
    is_lossless d_ms_hash_binding_semantic_category_choice_parameterized.
  rewrite /d_ms_hash_binding_semantic_category_choice_parameterized.
  apply dmap_ll.
  rewrite /d_ms_hash_binding_semantic_slot_choice_parameterized.
  apply drange_ll.
  exact ParameterizedBudgetParameters.ms1_param_total_count_pos.
have Hgap :
    `|ms_view_distinguish_pr
        (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu ((d_ms3a_bitness_real_source xms) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_observable_divergence_condition
           (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  rewrite /d_ms_after_binding_public_semantic_observable_v2_parameterized.
  rewrite /d_ms_hash_binding_public_semantic_observable_v2_parameterized.
  rewrite /d_ms_hash_binding_semantic_coupled_state_parameterized.
  rewrite (dmap_comp
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable)
    ((d_ms3a_bitness_real_source xms) `*`
     d_ms_hash_binding_semantic_category_choice_parameterized)).
  have Hright :
      d_ms_after_binding_observable_v2 x s xms =
      dmap ((d_ms3a_bitness_real_source xms) `*`
            d_ms_hash_binding_semantic_category_choice_parameterized)
        (ms3a_after_binding_observable_of_source \o fst).
  - rewrite /d_ms_after_binding_observable_v2.
    rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
      ((d_ms3a_bitness_real_source xms) `*`
       d_ms_hash_binding_semantic_category_choice_parameterized)).
    rewrite (L_dmap_dprod_fst_lossless
      (d_ms3a_bitness_real_source xms)
      d_ms_hash_binding_semantic_category_choice_parameterized
      Hcategory_ll).
    by [].
  rewrite Hright.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    ((d_ms3a_bitness_real_source xms) `*`
     d_ms_hash_binding_semantic_category_choice_parameterized)
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p)).`mshbss_observed_observable)
    (ms3a_after_binding_observable_of_source \o fst)
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_public_observable_divergence_condition
        (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) D).
  move=> p Hnodiv.
  rewrite /(\o) /=.
  rewrite /ms_hash_binding_public_observable_divergence_condition in Hnodiv.
  rewrite /ms_hash_binding_semantic_state_of_category_source /=.
  rewrite /ms_hash_binding_semantic_state_of_category_source /= in Hnodiv.
  rewrite /ms_hash_binding_observed_digest_of_category_source.
  rewrite /ms_hash_binding_observed_digest_of_category_source in Hnodiv.
  rewrite /ms_hash_binding_observable_of_source_digest.
  rewrite /ms_hash_binding_observable_of_source_digest in Hnodiv.
  rewrite /ms3a_after_binding_observable_of_source.
  rewrite /ms3a_after_binding_observable_of_source in Hnodiv.
  rewrite /ms_hash_binding_expected_transcript_digest_of_source.
  rewrite /ms_hash_binding_expected_transcript_digest_of_source in Hnodiv.
  rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
  rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /= in Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr
      (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr
        (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr
       (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass_parameterized xms.
rewrite /d_ms_hash_binding_semantic_coupled_state_parameterized dmapE /mu /= in Hmass.
rewrite /(\o) /= in Hmass.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma d_ms_after_binding_observable_v2_public_semantic_clean_image_parameterizedE
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_binding_observable_v2 x s xms =
  dmap (d_ms_rom_semantic_coupled_state_parameterized xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false).
proof.
rewrite d_ms_after_binding_observable_v2_canonical.
rewrite (dmap_const_ll (d_ms_rom_semantic_coupled_state_parameterized xms)
  (ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
  (d_ms_rom_semantic_coupled_state_parameterized_lossless xms)).
by rewrite /ms_rom_semantic_after_rom_observable_of_failure_flag.
qed.

lemma L_ms2_public_after_rom_transition_le_execution_owned_live_parameterized_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D <=
  ms_rom_execution_owned_parameterized_failure_probability xms.
proof.
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
  ms_rom_public_observable_divergence_mass_le_execution_owned_live_parameterized_failure xms.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma L_ms2_rom_programming_transition_le_execution_owned_live_parameterized_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D <=
  ms_rom_execution_owned_parameterized_failure_probability xms.
proof.
exact (L_ms2_public_after_rom_transition_le_execution_owned_live_parameterized_failure x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_public_endpoint_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D
  <= ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_live_parameterized_failure x s xms D.
have Hbridge :=
  A_MS2_rom_programming_execution_owned_parameterized_bound xms.
exact (ler_trans _ _ _ Hsemantic Hbridge).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
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
    (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D
  <= ms_hash_binding_local_public_divergence_upper_mass_parameterized +
     ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
have Hms1 :=
  A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound x s xms D.
have Hms2 :=
  A_MS2_rom_programming_parameterized_public_endpoint_transition_bound x s xms D.
have -> :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D =
  (ms_view_distinguish_pr
     (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
   ms_view_distinguish_pr
     (d_ms_after_binding_observable_v2 x s xms) D) +
  (ms_view_distinguish_pr
     (d_ms_after_binding_observable_v2 x s xms) D -
   ms_view_distinguish_pr
     (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hms1 Hms2).
qed.