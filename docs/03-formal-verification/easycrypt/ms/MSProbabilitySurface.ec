require import AllCore List Distr.
require import SDist.
require import StdOrder.
require import QssmTypes Algebra.
require import FS.
require import TranscriptObservable.
require import MS.
require import SourceTypes SourceModel.
require import SourceConstructors SourcePayloadDistributions.
require import SourceBitnessDistributions SourceObservableDistributions.
require import SourceHashBindingSemanticBridge.
require import ComparisonCouplingMarginals.
require import ComparisonPayloadTypes ComparisonPayloadSeedTypes.
require import ComparisonPayloadSemanticBridge.
(*---*) import RealOrder.

(* Minimal MS-side probability interface below `games/GameAdvantage.ec`.

   This file introduces the lower observable/probability surface now used by
   `games/GameAdvantage.ec` to define `game_pr_ms_core` on MS views.

   Current status:
   - Real/Sim endpoints already have concrete observable laws from
     `ms/source/SourceObservableDistributions.ec`.
   - AfterBinding now reuses the real source law and normalizes the public
     transcript digest by construction.
   - AfterRom now reuses the real source law plus the sampled comparison
     challenge-seed surface, while AfterBitness / AfterComparison still remain
     point-mass placeholders at the canonical public v2 observable.
   - MS1 is now wired upward through `game_pr_ms_core` and proved there.
     MS2 still remains axiomatized at the game layer until its lower
     transition theorem closes. *)

op ms_distinguisher_event (D : distinguisher) : ms_v2_transcript_observable -> bool =
  fun (obs : ms_v2_transcript_observable) =>
    qssm_distinguisher_event D
      (qssm_observable_event_payload (ms_qssm_event_payload obs)).

op ms_view_distinguish_pr (d : ms_v2_transcript_observable distr) (D : distinguisher) : real =
  mu d (ms_distinguisher_event D).

lemma ms_distinguisher_event_on_qssm_view_projection
  (v : qssm_public_view) (D : distinguisher) :
  ms_distinguisher_event D (qssm_view_to_ms_observable v) =
  qssm_distinguisher_event D
    (qssm_observable_event_payload v.`qssmpv_event_payload).
proof.
rewrite /ms_distinguisher_event.
by rewrite qssm_view_to_ms_observable_preserves_event_payload.
qed.

lemma ms_view_distinguish_pr_respects_distribution_equality
  (d d' : ms_v2_transcript_observable distr) (D : distinguisher) :
  d = d' => ms_view_distinguish_pr d D = ms_view_distinguish_pr d' D.
proof. by move=> ->. qed.

op d_ms_after_binding_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  dmap (d_ms3a_bitness_real_source xms)
    ms3a_after_binding_observable_of_source.

lemma d_ms_after_binding_observable_v2_canonical
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_binding_observable_v2 x s xms =
  dunit (ms3a_pack_observable_with_digest
    (ms3a_public_stmt_digest xms)
    (ms3a_public_result_bit xms)
    (ms3a_public_bitness_globals xms)
    (ms3a_public_comparison_global xms)).
proof.
rewrite /d_ms_after_binding_observable_v2.
rewrite ms3a_bitness_real_source_as_seed_dmap.
rewrite (dmap_comp
  (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed xms)
  ms3a_after_binding_observable_of_source
  (d_ms3a_real_payload_seed xms)).
rewrite /d_ms3a_real_payload_seed.
rewrite (dmap_comp ms3a_real_payload_seed_of_bitness_layer
  (ms3a_after_binding_observable_of_source \o
   (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed xms))
  (dunit (ms3a_canonical_public_source xms))).
rewrite dmap_dunit.
by rewrite /ms3a_after_binding_observable_of_source
  /ms3a_real_payload_from_seed /ms3a_bitness_layer_source_of_real_payload
  /(\o)
  /ms3a_real_payload_seed_of_bitness_layer /ms3a_canonical_public_source
  /ms3a_make_real_source /=.
qed.

lemma L_ms1_real_after_binding_distribution_eq_if_public_transcript_shape_ok
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms3a_public_transcript_shape_ok xms =>
  d_ms3a_bitness_real_observable_v2 xms = d_ms_after_binding_observable_v2 x s xms.
proof.
move=> Hshape.
rewrite d_ms3a_bitness_real_observable_v2_canonical
        d_ms_after_binding_observable_v2_canonical.
apply qssm_dunit_eq.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
have -> : ms3a_public_transcript_digest xms =
  ms3a_pack_observable_with_digest_digest
    (ms3a_public_stmt_digest xms)
    (ms3a_public_result_bit xms)
    (ms3a_public_bitness_globals xms)
    (ms3a_public_comparison_global xms).
- exact (ms3a_public_transcript_shape_ok_implies_digest_by_construction xms Hshape).
by [].
qed.

lemma L_ms1_hash_binding_bad_event_zero_if_public_transcript_shape_ok
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms3a_public_transcript_shape_ok xms =>
  ms_view_distinguish_pr (d_ms3a_bitness_real_observable_v2 xms) D =
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D.
proof.
move=> Hshape.
apply (ms_view_distinguish_pr_respects_distribution_equality
  (d_ms3a_bitness_real_observable_v2 xms)
  (d_ms_after_binding_observable_v2 x s xms) D).
exact (L_ms1_real_after_binding_distribution_eq_if_public_transcript_shape_ok x s xms Hshape).
qed.

lemma L_ms1_hash_binding_bad_event_zero_if_public_digest_eq_canonical
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms3a_public_transcript_digest xms =
    ms3a_pack_observable_with_digest_digest
      (ms3a_public_stmt_digest xms)
      (ms3a_public_result_bit xms)
      (ms3a_public_bitness_globals xms)
      (ms3a_public_comparison_global xms) =>
  ms_view_distinguish_pr (d_ms3a_bitness_real_observable_v2 xms) D =
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D.
proof.
move=> Hdigest.
have Hshape : ms3a_public_transcript_shape_ok xms.
- by rewrite (ms3a_public_transcript_shape_ok_iff_digest_by_construction xms).
exact (L_ms1_hash_binding_bad_event_zero_if_public_transcript_shape_ok x s xms D Hshape).
qed.

lemma L_ms1_hash_binding_bad_event_zero
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms3a_bitness_real_observable_v2 xms) D =
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D.
proof.
apply (L_ms1_hash_binding_bad_event_zero_if_public_digest_eq_canonical x s xms D).
exact (ms3a_public_transcript_digest_by_construction xms).
qed.

op d_ms_after_rom_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  dmap (d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms)
    (fun (sigma : ms3a_bitness_layer_source * ms3c_real_seed_challenge) =>
      ms3a_after_rom_observable_of_source_challenge sigma.`1 sigma.`2).

lemma L_ms2_real_source_distribution_canonical
  (x : ms_public_input) :
  d_ms3a_bitness_real_source x = dunit (ms3a_canonical_public_source x).
proof.
rewrite ms3a_bitness_real_source_as_seed_dmap.
rewrite /d_ms3a_real_payload_seed.
rewrite (dmap_comp ms3a_real_payload_seed_of_bitness_layer
  (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed x)
  (dunit (ms3a_canonical_public_source x))).
rewrite dmap_dunit.
by rewrite /ms3a_real_payload_from_seed /ms3a_real_payload_seed_of_bitness_layer
  /ms3a_bitness_layer_source_of_real_payload /ms3a_canonical_public_source /ms3a_make_real_source /(\o) /=.
qed.

lemma L_ms2_real_source_comparison_global_on_support
  (x : ms_public_input) (src : ms3a_bitness_layer_source) :
  src \in d_ms3a_bitness_real_source x =>
  src.`ms3s_comparison_global_challenge = ms3a_public_comparison_global x.
proof.
move=> Hsrc.
rewrite L_ms2_real_source_distribution_canonical supp_dunit in Hsrc.
move: Hsrc=> ->.
by rewrite /ms3a_canonical_public_source /ms3a_public_comparison_global /ms3a_make_real_source /=.
qed.

lemma d_ms_after_rom_observable_v2_eq_after_binding
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_rom_observable_v2 x s xms =
  d_ms_after_binding_observable_v2 x s xms.
proof.
rewrite /d_ms_after_rom_observable_v2 /d_ms_after_binding_observable_v2.
have Hmid :
  dmap (d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms)
    (fun (sigma : ms3a_bitness_layer_source * ms3c_real_seed_challenge) =>
      ms3a_after_rom_observable_of_source_challenge sigma.`1 sigma.`2) =
  dmap (d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms)
    (ms3a_after_binding_observable_of_source \o fst).
- apply eq_dmap_in=> sigma Hsigma /=.
  rewrite supp_dprod in Hsigma.
  move: Hsigma=> [Hsrc Hsc].
  have Hsrcglob :=
    L_ms2_real_source_comparison_global_on_support xms sigma.`1 Hsrc.
  have [_ [_ [_ [_ [_ [_ [Hprog _]]]]]]] :=
    L_ms3c_real_seed_challenge_on_support_public_surface xms sigma.`2 Hsc.
  rewrite /(\o) /=.
  rewrite /ms3a_after_rom_observable_of_source_challenge.
  rewrite /ms3a_after_binding_observable_of_source /ms3c_seed_challenge_programmed_global.
  by rewrite Hsrcglob Hprog.
rewrite Hmid.
rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
  (d_ms3a_bitness_real_source xms `*` d_ms3c_real_seed_challenge xms)).
rewrite (L_dmap_dprod_fst_lossless
  (d_ms3a_bitness_real_source xms)
  (d_ms3c_real_seed_challenge xms)
  (L_ms3c_real_seed_challenge_lossless xms)).
by [].
qed.

lemma d_ms_after_rom_observable_v2_canonical
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_rom_observable_v2 x s xms =
  dunit (ms3a_pack_observable_with_digest
    (ms3a_public_stmt_digest xms)
    (ms3a_public_result_bit xms)
    (ms3a_public_bitness_globals xms)
    (ms3a_public_comparison_global xms)).
proof.
rewrite d_ms_after_rom_observable_v2_eq_after_binding.
exact (d_ms_after_binding_observable_v2_canonical x s xms).
qed.

op d_ms_after_rom_semantic_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  dmap (d_ms_rom_semantic_coupled_state xms)
    (ms_rom_semantic_after_rom_observable_of_state xms).

lemma d_ms_after_binding_observable_v2_semantic_clean_imageE
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_binding_observable_v2 x s xms =
  dmap (dunit false)
    (ms_rom_semantic_after_rom_observable_of_failure_flag xms).
proof.
rewrite d_ms_after_binding_observable_v2_canonical.
rewrite dmap_dunit.
by rewrite /ms_rom_semantic_after_rom_observable_of_failure_flag.
qed.

lemma d_ms_after_rom_semantic_observable_v2_failure_choiceE
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_rom_semantic_observable_v2 x s xms =
  dmap (d_ms_rom_semantic_failure_state_choice xms)
    (ms_rom_semantic_after_rom_observable_of_failure_flag xms).
proof.
rewrite /d_ms_after_rom_semantic_observable_v2.
have Hmap :
  dmap (d_ms_rom_semantic_coupled_state xms)
    (ms_rom_semantic_after_rom_observable_of_state xms) =
  dmap (d_ms_rom_semantic_coupled_state xms)
    ((ms_rom_semantic_after_rom_observable_of_failure_flag xms) \o
      ms_rom_semantic_failure_event).
- apply eq_dmap_in=> st _ /=.
  by rewrite /(\o) ms_rom_semantic_after_rom_observable_of_stateE.
rewrite Hmap.
rewrite -(dmap_comp ms_rom_semantic_failure_event
  (ms_rom_semantic_after_rom_observable_of_failure_flag xms)
  (d_ms_rom_semantic_coupled_state xms)).
by rewrite /d_ms_rom_semantic_failure_state_choice.
qed.

lemma ms_rom_semantic_failure_state_choice_sdist_dunit_false_le_failure_probability
  (xms : ms_public_input) :
  sdist (d_ms_rom_semantic_failure_state_choice xms) (dunit false) <=
  ms_rom_execution_owned_semantic_failure_probability xms.
proof.
have Hfailure_nonneg :
    0%r <= ms_rom_execution_owned_semantic_failure_probability xms.
  rewrite ms_rom_execution_owned_semantic_failure_probability_eq_local_mass.
  rewrite ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic.
  exact A2_ms_rom_programmability_semantic_nonneg.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE :
        mu (d_ms_rom_semantic_failure_state_choice xms) E =
        mu (d_ms_rom_semantic_failure_state_choice xms) predT.
      apply/mu_eq=> bad /=.
      by case: bad=> /=; rewrite ?Ef ?Et.
    have Hw : weight (d_ms_rom_semantic_failure_state_choice xms) = 1%r.
      exact (is_losslessP _
        (d_ms_rom_semantic_failure_state_choice_lossless xms)).
    rewrite HE /weight Hw.
    have -> : 1%r - 1%r = 0%r by ring.
    exact Hfailure_nonneg.
  have HE :
      mu (d_ms_rom_semantic_failure_state_choice xms) E =
      mu1 (d_ms_rom_semantic_failure_state_choice xms) false.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE d_ms_rom_semantic_failure_state_choice_mass_false.
  rewrite /ms_rom_execution_owned_semantic_failure_probability.
  rewrite d_ms_rom_semantic_failure_state_choiceE.
  rewrite ms_rom_semantic_failure_choice_mass_true.
  rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form.
  rewrite BudgetParameters.ms_rom_failure_slot_count_demo_closed_form /=.
  by smt().
case (E true) => [Et|Et] /=.
  have HE :
      mu (d_ms_rom_semantic_failure_state_choice xms) E =
      mu1 (d_ms_rom_semantic_failure_state_choice xms) true.
    apply/mu_eq=> bad /=.
    by case: bad=> /=; rewrite ?Ef ?Et.
  rewrite HE /ms_rom_execution_owned_semantic_failure_probability.
  by smt().
have HE :
    mu (d_ms_rom_semantic_failure_state_choice xms) E =
    mu (d_ms_rom_semantic_failure_state_choice xms) pred0.
  apply/mu_eq=> bad /=.
  by case: bad=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
exact Hfailure_nonneg.
qed.

lemma L_ms2_rom_programming_transition_le_execution_owned_semantic_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_rom_semantic_observable_v2 x s xms) D <=
  ms_rom_execution_owned_semantic_failure_probability xms.
proof.
pose db := d_ms_after_binding_observable_v2 x s xms.
pose dsem := d_ms_after_rom_semantic_observable_v2 x s xms.
pose E := ms_distinguisher_event D.
have Hsdist :
    sdist db dsem <= ms_rom_execution_owned_semantic_failure_probability xms.
  rewrite /db /dsem.
  rewrite d_ms_after_binding_observable_v2_semantic_clean_imageE.
  rewrite d_ms_after_rom_semantic_observable_v2_failure_choiceE.
  pose F := ms_rom_semantic_after_rom_observable_of_failure_flag xms.
  have Hmap :
    sdist (dmap (dunit false) F)
      (dmap (d_ms_rom_semantic_failure_state_choice xms) F) <=
    sdist (dunit false) (d_ms_rom_semantic_failure_state_choice xms).
    exact (sdist_dmap (dunit false)
      (d_ms_rom_semantic_failure_state_choice xms) F).
  apply (ler_trans _ _ _ Hmap).
  rewrite sdistC.
  exact (ms_rom_semantic_failure_state_choice_sdist_dunit_false_le_failure_probability xms).
have Habs : `|mu db E - mu dsem E| <= sdist db dsem.
  exact (sdist_upper_bound db dsem E).
have Hle : mu db E - mu dsem E <= `|mu db E - mu dsem E|.
  exact (ler_norm (mu db E - mu dsem E)).
apply (ler_trans _ _ _ Hle).
apply (ler_trans _ _ _ Habs Hsdist).
qed.

op d_ms_game_stage_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (st : ms_game_stage) : ms_v2_transcript_observable distr =
  with st = MSGameStageReal =>
    d_ms3a_bitness_real_observable_v2 xms
  with st = MSGameStageAfterBinding =>
    d_ms_after_binding_observable_v2 x s xms
  with st = MSGameStageAfterRom =>
    d_ms_after_rom_observable_v2 x s xms
  with st = MSGameStageAfterBitness =>
    dunit (ms3a_public_v2_observable xms)
  with st = MSGameStageAfterComparison =>
    dunit (ms3a_public_v2_observable xms)
  with st = MSGameStageSim =>
    d_ms3a_bitness_sim_observable_v2 xms s.

lemma L_ms1_hash_binding_stage_zero
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
proof.
rewrite /d_ms_game_stage_observable_v2 /=.
exact (L_ms1_hash_binding_bad_event_zero x s xms D).
qed.

lemma A_MS1_hash_binding_bad_event_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D
  <= epsilon_ms_hash_binding.
proof.
have Heq := L_ms1_hash_binding_stage_zero x s xms D.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
- exact Heq.
exact A1_ms_hash_binding_nonneg.
qed.

lemma A_MS1_hash_binding_semantic_bad_event_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D
  <= MS.epsilon_ms_hash_binding_semantic.
proof.
have Heq := L_ms1_hash_binding_stage_zero x s xms D.
have Hbridge := A_MS1_hash_binding_execution_owned_semantic_bound xms.
have Hfailure_nonneg :
    0%r <= ms_hash_binding_execution_owned_semantic_failure_probability xms.
  rewrite ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass.
  rewrite ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic.
  have Hnonneg := MS.A1_ms_hash_binding_semantic_nonneg.
  rewrite /MS.epsilon_ms_hash_binding_semantic in Hnonneg.
  exact Hnonneg.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
- exact Heq.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D = 0%r.
  by ring.
have Hbound : 0%r <= BudgetParameters.epsilon_ms_hash_binding_semantic.
  exact (ler_trans _ _ _ Hfailure_nonneg Hbridge).
rewrite /MS.epsilon_ms_hash_binding_semantic.
exact Hbound.
qed.

lemma L_ms2_rom_programming_transition_zero
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D.
proof.
rewrite /d_ms_game_stage_observable_v2 /=.
apply (ms_view_distinguish_pr_respects_distribution_equality
  (d_ms_after_binding_observable_v2 x s xms)
  (d_ms_after_rom_observable_v2 x s xms) D).
by rewrite -d_ms_after_rom_observable_v2_eq_after_binding.
qed.

lemma A_MS2_rom_programming_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D
  <= epsilon_ms_rom_programmability.
proof.
have Heq := L_ms2_rom_programming_transition_zero x s xms D.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D.
- exact Heq.
exact A2_ms_rom_programmability_nonneg.
qed.

lemma A_MS2_rom_programming_semantic_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D
  <= epsilon_ms_rom_programmability_semantic.
proof.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_semantic_failure x s xms D.
have Hbridge := A_MS2_rom_programming_execution_owned_semantic_bound xms.
have Hfailure_nonneg :
    0%r <= ms_rom_execution_owned_semantic_failure_probability xms.
  rewrite ms_rom_execution_owned_semantic_failure_probability_eq_local_mass.
  rewrite ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic.
  exact A2_ms_rom_programmability_semantic_nonneg.
have Hsemantic_endpoint_budget :
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D -
    ms_view_distinguish_pr
      (d_ms_after_rom_semantic_observable_v2 x s xms) D <=
    epsilon_ms_rom_programmability_semantic.
  rewrite /d_ms_game_stage_observable_v2 /=.
  exact (ler_trans _ _ _ Hsemantic Hbridge).
have Heq :
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D =
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D.
  rewrite /d_ms_game_stage_observable_v2 /=.
  apply (ms_view_distinguish_pr_respects_distribution_equality
    (d_ms_after_binding_observable_v2 x s xms)
    (d_ms_after_rom_observable_v2 x s xms) D).
  by rewrite -d_ms_after_rom_observable_v2_eq_after_binding.
rewrite Heq.
  have -> :
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D -
    ms_view_distinguish_pr
      (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterRom) D =
    0%r by ring.
have Hbudget_nonneg : 0%r <= epsilon_ms_rom_programmability_semantic.
  exact (ler_trans _ _ _ Hfailure_nonneg Hbridge).
exact Hbudget_nonneg.
qed.

(* Remaining lower theorem target at this boundary.

  The current MS2 lower semantic lane now also exposes an execution-owned
  semantic AfterRom endpoint and a non-identity bound against it, while the
  public AfterBinding/AfterRom stage pair itself still collapses by exact
  equality under the current real seed-challenge law. The remaining MS2 work
  is to retarget the public AfterRom stage away from that exact-equality
  carrier and then remove `A_MS2_rom_programming_game_pr_core_bound`. *)
