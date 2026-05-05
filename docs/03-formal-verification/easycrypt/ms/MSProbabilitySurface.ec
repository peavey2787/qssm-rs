require import AllCore List Distr.
require import QssmTypes Algebra.
require import FS.
require import TranscriptObservable.
require import MS.
require import SourceTypes SourceModel.
require import SourceConstructors SourcePayloadDistributions.
require import SourceBitnessDistributions SourceObservableDistributions.
require import ComparisonCouplingMarginals.
require import ComparisonPayloadTypes ComparisonPayloadSeedTypes.

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

(* Remaining lower theorem target at this boundary.

   The current MS2 lower theorem closes because the existing real seed-challenge
   surface already keeps `ms3csc_programmed_challenge` pinned to the native
   public comparison-global digest on support. The remaining MS2 work is now the
   game-layer bridge that removes `A_MS2_rom_programming_game_pr_core_bound`. *)
