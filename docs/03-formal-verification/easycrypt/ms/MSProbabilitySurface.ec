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

lemma dmap_const_ll ['a 'b] (d : 'a distr) (v : 'b) :
  is_lossless d =>
  dmap d (fun _ : 'a => v) = dunit v.
proof.
move=> ll_d.
rewrite /dmap dlet_cst_weight (is_losslessP _ ll_d).
by rewrite dscalar1.
qed.

lemma ms_same_source_distinguisher_gap_le_bad_mass ['a]
  (d : 'a distr)
  (f g : 'a -> ms_v2_transcript_observable)
  (bad : 'a -> bool) (D : distinguisher) :
  (forall x, ! bad x => f x = g x) =>
  `|ms_view_distinguish_pr (dmap d f) D -
    ms_view_distinguish_pr (dmap d g) D| <=
  mu d bad.
proof.
move=> Hagree.
rewrite /ms_view_distinguish_pr !dmapE /=.
have Hf_split :
    mu d (fun x => ms_distinguisher_event D (f x)) =
    mu d (fun x => ms_distinguisher_event D (f x) /\ bad x) +
    mu d (fun x => ms_distinguisher_event D (f x) /\ ! bad x).
  by rewrite (mu_split d (fun x => ms_distinguisher_event D (f x)) bad)
    /predI /predC /=.
have Hg_split :
    mu d (fun x => ms_distinguisher_event D (g x)) =
    mu d (fun x => ms_distinguisher_event D (g x) /\ bad x) +
    mu d (fun x => ms_distinguisher_event D (g x) /\ ! bad x).
  by rewrite (mu_split d (fun x => ms_distinguisher_event D (g x)) bad)
    /predI /predC /=.
have Hclean_eq :
    mu d (fun x => ms_distinguisher_event D (f x) /\ ! bad x) =
    mu d (fun x => ms_distinguisher_event D (g x) /\ ! bad x).
  apply/mu_eq=> x /=.
  have [Hbad|Hgood] : bad x \/ ! bad x by smt().
  - by rewrite Hbad.
  have -> : f x = g x.
    exact (Hagree x Hgood).
  by [].
rewrite Hf_split Hg_split Hclean_eq.
have Hf_bad_le :
    mu d (fun x => ms_distinguisher_event D (f x) /\ bad x) <=
    mu d bad.
  apply mu_sub => x /=.
  by smt().
have Hg_bad_le :
    mu d (fun x => ms_distinguisher_event D (g x) /\ bad x) <=
    mu d bad.
  apply mu_sub => x /=.
  by smt().
by smt(mu_bounded).
qed.

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

op d_ms_after_binding_public_semantic_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  d_ms_hash_binding_public_semantic_observable_v2 xms.

lemma L_ms1_public_after_binding_transition_le_local_public_divergence_upper_mass
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D <=
  ms_hash_binding_local_public_divergence_upper_mass.
proof.
have Hcategory_ll :
    is_lossless d_ms_hash_binding_semantic_category_choice.
  rewrite /d_ms_hash_binding_semantic_category_choice.
  by apply dmap_ll; exact ms_hash_binding_semantic_slot_choice_lossless.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D| <=
    mu ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_observable_divergence_condition
           (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  rewrite /d_ms_after_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_semantic_coupled_state.
  rewrite (dmap_comp
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable)
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
  have Hleft :
      d_ms_after_binding_observable_v2 x s xms =
      dmap ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
        (ms3a_after_binding_observable_of_source \o fst).
  - rewrite /d_ms_after_binding_observable_v2.
    rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
      ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
    rewrite (L_dmap_dprod_fst_lossless
      (d_ms3a_bitness_real_source xms)
      d_ms_hash_binding_semantic_category_choice
      Hcategory_ll).
    by [].
  rewrite Hleft.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
    (ms3a_after_binding_observable_of_source \o fst)
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p)).`mshbss_observed_observable)
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
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D)).
have Hmass :=
  ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass xms.
rewrite /d_ms_hash_binding_semantic_coupled_state dmapE /mu /= in Hmass.
rewrite /(\o) /= in Hmass.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma L_ms1_public_after_binding_transition_le_execution_owned_semantic_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D <=
  ms_hash_binding_execution_owned_semantic_failure_probability xms.
proof.
have Hcategory_ll :
    is_lossless d_ms_hash_binding_semantic_category_choice.
  rewrite /d_ms_hash_binding_semantic_category_choice.
  by apply dmap_ll; exact ms_hash_binding_semantic_slot_choice_lossless.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D| <=
    mu ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_observable_divergence_condition
           (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  rewrite /d_ms_after_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_semantic_coupled_state.
  rewrite (dmap_comp
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable)
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
  have Hleft :
      d_ms_after_binding_observable_v2 x s xms =
      dmap ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
        (ms3a_after_binding_observable_of_source \o fst).
  - rewrite /d_ms_after_binding_observable_v2.
    rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
      ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
    rewrite (L_dmap_dprod_fst_lossless
      (d_ms3a_bitness_real_source xms)
      d_ms_hash_binding_semantic_category_choice
      Hcategory_ll).
    by [].
  rewrite Hleft.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
    (ms3a_after_binding_observable_of_source \o fst)
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p)).`mshbss_observed_observable)
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
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D)).
have Hmass :=
  ms_hash_binding_public_observable_divergence_mass_le_execution_owned_semantic_failure xms.
rewrite /d_ms_hash_binding_semantic_coupled_state dmapE /mu /= in Hmass.
rewrite /(\o) /= in Hmass.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma L_ms1_public_after_binding_compatibility_le_local_public_divergence_upper_mass
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
  ms_hash_binding_local_public_divergence_upper_mass.
proof.
have Hcategory_ll :
    is_lossless d_ms_hash_binding_semantic_category_choice.
  rewrite /d_ms_hash_binding_semantic_category_choice.
  by apply dmap_ll; exact ms_hash_binding_semantic_slot_choice_lossless.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_observable_divergence_condition
           (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  rewrite /d_ms_after_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_semantic_coupled_state.
  rewrite (dmap_comp
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable)
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
  have Hright :
      d_ms_after_binding_observable_v2 x s xms =
      dmap ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
        (ms3a_after_binding_observable_of_source \o fst).
  - rewrite /d_ms_after_binding_observable_v2.
    rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
      ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
    rewrite (L_dmap_dprod_fst_lossless
      (d_ms3a_bitness_real_source xms)
      d_ms_hash_binding_semantic_category_choice
      Hcategory_ll).
    by [].
  rewrite Hright.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
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
    ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  ms_hash_binding_public_observable_divergence_mass_le_local_public_divergence_upper_mass xms.
rewrite /d_ms_hash_binding_semantic_coupled_state dmapE /mu /= in Hmass.
rewrite /(\o) /= in Hmass.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma L_ms1_public_after_binding_compatibility_le_execution_owned_semantic_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
  ms_hash_binding_execution_owned_semantic_failure_probability xms.
proof.
have Hcategory_ll :
    is_lossless d_ms_hash_binding_semantic_category_choice.
  rewrite /d_ms_hash_binding_semantic_category_choice.
  by apply dmap_ll; exact ms_hash_binding_semantic_slot_choice_lossless.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D| <=
    mu ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_public_observable_divergence_condition
           (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  rewrite /d_ms_after_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_public_semantic_observable_v2.
  rewrite /d_ms_hash_binding_semantic_coupled_state.
  rewrite (dmap_comp
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable)
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
  have Hright :
      d_ms_after_binding_observable_v2 x s xms =
      dmap ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
        (ms3a_after_binding_observable_of_source \o fst).
  - rewrite /d_ms_after_binding_observable_v2.
    rewrite -(dmap_comp fst ms3a_after_binding_observable_of_source
      ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)).
    rewrite (L_dmap_dprod_fst_lossless
      (d_ms3a_bitness_real_source xms)
      d_ms_hash_binding_semantic_category_choice
      Hcategory_ll).
    by [].
  rewrite Hright.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    ((d_ms3a_bitness_real_source xms) `*` d_ms_hash_binding_semantic_category_choice)
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
    ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D)).
have Hmass :=
  ms_hash_binding_public_observable_divergence_mass_le_execution_owned_semantic_failure xms.
rewrite /d_ms_hash_binding_semantic_coupled_state dmapE /mu /= in Hmass.
rewrite /(\o) /= in Hmass.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
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

op d_ms_after_rom_public_semantic_observable_v2
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  dmap (d_ms_rom_semantic_coupled_state xms)
    (ms_after_rom_public_semantic_observable_of_state xms).

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

lemma d_ms_after_binding_observable_v2_public_semantic_clean_imageE
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  d_ms_after_binding_observable_v2 x s xms =
  dmap (d_ms_rom_semantic_coupled_state xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false).
proof.
rewrite d_ms_after_binding_observable_v2_canonical.
rewrite (dmap_const_ll (d_ms_rom_semantic_coupled_state xms)
  (ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
  (d_ms_rom_semantic_coupled_state_lossless xms)).
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

lemma L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
  ms_rom_execution_owned_semantic_failure_probability xms.
proof.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_imageE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
    (ms_after_rom_public_semantic_observable_of_state xms)
    (ms_rom_public_observable_divergence_condition xms) D).
  move=> st Hnodiv.
  have Hobs :=
    ms_after_rom_public_semantic_observable_of_state_no_divergenceE xms st Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D)).
have Hmass :=
  ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure xms.
apply (ler_trans _ _ _ Hdir).
exact (ler_trans _ _ _ Hgap Hmass).
qed.

lemma L_ms2_public_after_rom_transition_le_public_observable_divergence_mass
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
  ms_rom_public_observable_divergence_mass xms.
proof.
have Hgap :
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D| <=
    mu (d_ms_rom_semantic_coupled_state xms)
      (ms_rom_public_observable_divergence_condition xms).
  rewrite d_ms_after_binding_observable_v2_public_semantic_clean_imageE.
  rewrite /d_ms_after_rom_public_semantic_observable_v2.
  apply (ms_same_source_distinguisher_gap_le_bad_mass
    (d_ms_rom_semantic_coupled_state xms)
    (fun _ : ms_rom_semantic_state =>
      ms_rom_semantic_after_rom_observable_of_failure_flag xms false)
    (ms_after_rom_public_semantic_observable_of_state xms)
    (ms_rom_public_observable_divergence_condition xms) D).
  move=> st Hnodiv.
  have Hobs :=
    ms_after_rom_public_semantic_observable_of_state_no_divergenceE xms st Hnodiv.
  by smt().
have Hdir :
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
    `|ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
      ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D|.
  exact (ler_norm
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D)).
rewrite /ms_rom_public_observable_divergence_mass.
exact (ler_trans _ _ _ Hdir Hgap).
qed.

lemma L_ms2_public_after_rom_transition_le_public_visible_flags_mass
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
  ((if ms_rom_public_divergence_global_digest_flag xms then
      (BudgetParameters.ms_rom_query_collision_slot_count +
       BudgetParameters.ms_rom_programming_collision_slot_count)%r
    else 0%r) +
   (if ms_rom_public_divergence_query_digest_flag xms then
      BudgetParameters.ms_rom_transcript_mismatch_slot_count%r
    else 0%r)) /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite -(ms_rom_public_observable_divergence_mass_flagsE xms).
exact (L_ms2_public_after_rom_transition_le_public_observable_divergence_mass x s xms D).
qed.

lemma L_ms2_rom_programming_transition_le_execution_owned_semantic_failure
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
  ms_rom_execution_owned_semantic_failure_probability xms.
proof.
exact (L_ms2_public_after_rom_transition_le_execution_owned_semantic_failure x s xms D).
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

lemma A_MS1_hash_binding_semantic_observable_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D -
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D
  <= MS.epsilon_ms_hash_binding_semantic.
proof.
have Heq := L_ms1_hash_binding_stage_zero x s xms D.
have Hsemantic :=
  L_ms1_public_after_binding_transition_le_execution_owned_semantic_failure x s xms D.
have Hbridge := A_MS1_hash_binding_execution_owned_semantic_bound xms.
have -> :
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageReal) D =
  ms_view_distinguish_pr
    (d_ms_game_stage_observable_v2 x s xms MSGameStageAfterBinding) D.
- exact Heq.
rewrite /d_ms_game_stage_observable_v2 /=.
rewrite /MS.epsilon_ms_hash_binding_semantic.
exact (ler_trans _ _ _ Hsemantic Hbridge).
qed.

lemma A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D
  <= MS.epsilon_ms_hash_binding_semantic.
proof.
have Hsemantic :=
  L_ms1_public_after_binding_compatibility_le_execution_owned_semantic_failure x s xms D.
have Hbridge := A_MS1_hash_binding_execution_owned_semantic_bound xms.
rewrite /MS.epsilon_ms_hash_binding_semantic.
exact (ler_trans _ _ _ Hsemantic Hbridge).
qed.

lemma A_MS2_rom_programming_semantic_public_endpoint_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= epsilon_ms_rom_programmability_semantic.
proof.
have Hsemantic :=
  L_ms2_rom_programming_transition_le_execution_owned_semantic_failure x s xms D.
have Hbridge := A_MS2_rom_programming_execution_owned_semantic_bound xms.
exact (ler_trans _ _ _ Hsemantic Hbridge).
qed.

lemma A_MS1_to_MS2_semantic_public_endpoint_transition_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= MS.epsilon_ms_hash_binding_semantic +
     epsilon_ms_rom_programmability_semantic.
proof.
have Hms1 :=
  A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound x s xms D.
have Hms2 :=
  A_MS2_rom_programming_semantic_public_endpoint_transition_bound x s xms D.
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

lemma A_MS1_to_MS2_semantic_public_endpoint_visible_flags_bound
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) (D : distinguisher) :
  ms_view_distinguish_pr
    (d_ms_after_binding_public_semantic_observable_v2 x s xms) D -
  ms_view_distinguish_pr
    (d_ms_after_rom_public_semantic_observable_v2 x s xms) D
  <= MS.epsilon_ms_hash_binding_semantic +
     ((if ms_rom_public_divergence_global_digest_flag xms then
         (BudgetParameters.ms_rom_query_collision_slot_count +
          BudgetParameters.ms_rom_programming_collision_slot_count)%r
       else 0%r) +
      (if ms_rom_public_divergence_query_digest_flag xms then
         BudgetParameters.ms_rom_transcript_mismatch_slot_count%r
       else 0%r)) /
     BudgetParameters.ms_rom_total_slot_count%r.
proof.
have Hms1 :=
  A_MS1_hash_binding_semantic_public_endpoint_compatibility_bound x s xms D.
have Hms2 :=
  L_ms2_public_after_rom_transition_le_public_visible_flags_mass x s xms D.
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
      (d_ms_after_rom_public_semantic_observable_v2 x s xms) D <=
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
