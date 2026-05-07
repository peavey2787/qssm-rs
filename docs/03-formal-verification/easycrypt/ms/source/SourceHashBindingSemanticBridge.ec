require import AllCore Int List Distr.
require import QssmTypes.
require import BudgetParameters.
require import TranscriptObservable.
require import SourceTypes SourceModel.
require import SourceConstructors SourcePayloadDistributions.
require import SourceBitnessDistributions SourceObservableDistributions.
import Ring.IntID StdOrder.IntOrder Range.

(* Source-local semantic bridge for a future MS1 hash-binding semantic route.
   This file keeps the semantic owner below `MSProbabilitySurface.ec`: it
   couples the canonical MS-3a real source with a local primitive semantic
   category choice, gives each category an explicit source/public-observable
   state and witness shape, and closes the resulting failure mass against the
   primitive owner `epsilon_ms_hash_binding_semantic`.

   Nothing in this file rewires the active exact-zero MS1 route yet. *)

type ms_hash_binding_collision_witness = {
  mshbcw_expected_digest : digest;
  mshbcw_competing_digest : digest;
  mshbcw_present : bool;
}.

type ms_hash_binding_malformed_binding_witness = {
  mshbmbw_bound_digest : digest;
  mshbmbw_shape_ok : bool;
  mshbmbw_present : bool;
}.

type ms_hash_binding_semantic_state = {
  mshbss_category : BudgetParameters.ms_hash_binding_semantic_category;
  mshbss_real_source : ms3a_bitness_layer_source;
  mshbss_after_binding_observable : ms_v2_transcript_observable;
  mshbss_observed_observable : ms_v2_transcript_observable;
  mshbss_expected_transcript_digest : digest;
  mshbss_observed_transcript_digest : digest;
  mshbss_matches_expected : bool;
  mshbss_collision_witness : ms_hash_binding_collision_witness;
  mshbss_malformed_binding_witness : ms_hash_binding_malformed_binding_witness;
}.

op ms_hash_binding_expected_transcript_digest_of_source
  (src : ms3a_bitness_layer_source) : digest =
  ms3a_pack_observable_with_digest_digest
    src.`ms3s_stmt
    src.`ms3s_result
    src.`ms3s_bitness_global_challenges
    src.`ms3s_comparison_global_challenge.

op ms_hash_binding_observable_of_source_digest
  (src : ms3a_bitness_layer_source)
  (transcript_digest : digest) : ms_v2_transcript_observable =
  ms3a_pack_observable
    src.`ms3s_stmt
    src.`ms3s_result
    src.`ms3s_bitness_global_challenges
    src.`ms3s_comparison_global_challenge
    transcript_digest.

op ms_hash_binding_observed_digest_of_category_source
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) : digest =
  if pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category then
    src.`ms3s_stmt
  else if pred1 BudgetParameters.MSHashBindingSemanticTranscriptMismatch category then
    src.`ms3s_comparison_global_challenge
  else ms_hash_binding_expected_transcript_digest_of_source src.

op ms_hash_binding_collision_witness_of_category_source
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_collision_witness =
  let expected_digest =
    ms_hash_binding_expected_transcript_digest_of_source src in
  {| mshbcw_expected_digest = expected_digest;
     mshbcw_competing_digest = src.`ms3s_stmt;
     mshbcw_present =
       pred1 BudgetParameters.MSHashBindingSemanticCollision category |}.

op ms_hash_binding_malformed_binding_witness_of_category_source
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_malformed_binding_witness =
  let observed_digest =
    ms_hash_binding_observed_digest_of_category_source src category in
  {| mshbmbw_bound_digest = observed_digest;
     mshbmbw_shape_ok =
       ! pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category;
     mshbmbw_present =
       pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category |}.

op ms_hash_binding_semantic_state_of_category_source
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_semantic_state =
  let expected_digest =
    ms_hash_binding_expected_transcript_digest_of_source src in
  let observed_digest =
    ms_hash_binding_observed_digest_of_category_source src category in
  {| mshbss_category = category;
     mshbss_real_source = src;
     mshbss_after_binding_observable =
       ms3a_after_binding_observable_of_source src;
     mshbss_observed_observable =
       ms_hash_binding_observable_of_source_digest src observed_digest;
     mshbss_expected_transcript_digest = expected_digest;
     mshbss_observed_transcript_digest = observed_digest;
     mshbss_matches_expected =
       pred1 BudgetParameters.MSHashBindingSemanticClean category ||
       pred1 BudgetParameters.MSHashBindingSemanticCollision category;
     mshbss_collision_witness =
       ms_hash_binding_collision_witness_of_category_source src category;
     mshbss_malformed_binding_witness =
       ms_hash_binding_malformed_binding_witness_of_category_source src category |}.

op ms_hash_binding_public_observable_divergence_condition
  (st : ms_hash_binding_semantic_state) : bool =
  st.`mshbss_after_binding_observable.`msv2_transcript_digest <>
  st.`mshbss_observed_observable.`msv2_transcript_digest.

op ms_hash_binding_clean_condition
  (st : ms_hash_binding_semantic_state) : bool =
  ! st.`mshbss_collision_witness.`mshbcw_present /\
  ! st.`mshbss_malformed_binding_witness.`mshbmbw_present /\
  st.`mshbss_matches_expected /\
  st.`mshbss_after_binding_observable.`msv2_transcript_digest =
    st.`mshbss_expected_transcript_digest /\
  st.`mshbss_observed_observable.`msv2_transcript_digest =
    st.`mshbss_observed_transcript_digest /\
  st.`mshbss_observed_transcript_digest =
    st.`mshbss_expected_transcript_digest.

op ms_hash_binding_collision_condition
  (st : ms_hash_binding_semantic_state) : bool =
  st.`mshbss_collision_witness.`mshbcw_present /\
  st.`mshbss_collision_witness.`mshbcw_expected_digest =
    st.`mshbss_expected_transcript_digest /\
  ! st.`mshbss_malformed_binding_witness.`mshbmbw_present /\
  st.`mshbss_matches_expected /\
  st.`mshbss_observed_observable.`msv2_transcript_digest =
    st.`mshbss_observed_transcript_digest /\
  st.`mshbss_observed_transcript_digest =
    st.`mshbss_expected_transcript_digest.

op ms_hash_binding_malformed_binding_condition
  (st : ms_hash_binding_semantic_state) : bool =
  ! st.`mshbss_collision_witness.`mshbcw_present /\
  st.`mshbss_malformed_binding_witness.`mshbmbw_present /\
  ! st.`mshbss_malformed_binding_witness.`mshbmbw_shape_ok /\
  st.`mshbss_malformed_binding_witness.`mshbmbw_bound_digest =
    st.`mshbss_observed_transcript_digest /\
  st.`mshbss_observed_observable.`msv2_transcript_digest =
    st.`mshbss_observed_transcript_digest /\
  ! st.`mshbss_matches_expected.

op ms_hash_binding_transcript_mismatch_condition
  (st : ms_hash_binding_semantic_state) : bool =
  ! st.`mshbss_collision_witness.`mshbcw_present /\
  ! st.`mshbss_malformed_binding_witness.`mshbmbw_present /\
  ! st.`mshbss_matches_expected /\
  st.`mshbss_observed_observable.`msv2_transcript_digest =
    st.`mshbss_observed_transcript_digest.

op ms_hash_binding_semantic_category_condition
  (category : BudgetParameters.ms_hash_binding_semantic_category)
  (st : ms_hash_binding_semantic_state) : bool =
  if pred1 BudgetParameters.MSHashBindingSemanticClean category then
    ms_hash_binding_clean_condition st
  else if pred1 BudgetParameters.MSHashBindingSemanticCollision category then
    ms_hash_binding_collision_condition st
  else if pred1 BudgetParameters.MSHashBindingSemanticMalformedBinding category then
    ms_hash_binding_malformed_binding_condition st
  else ms_hash_binding_transcript_mismatch_condition st.

lemma ms_hash_binding_clean_condition_clean_categoryE
  (src : ms3a_bitness_layer_source) :
  ms_hash_binding_clean_condition
    (ms_hash_binding_semantic_state_of_category_source src
      BudgetParameters.MSHashBindingSemanticClean).
proof.
rewrite /ms_hash_binding_clean_condition.
rewrite /ms_hash_binding_semantic_state_of_category_source /=.
rewrite /ms_hash_binding_collision_witness_of_category_source.
rewrite /ms_hash_binding_malformed_binding_witness_of_category_source.
rewrite /ms_hash_binding_expected_transcript_digest_of_source.
rewrite /ms_hash_binding_observed_digest_of_category_source.
rewrite /ms_hash_binding_observable_of_source_digest.
rewrite /ms3a_after_binding_observable_of_source.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
by rewrite /pred1 /=.
qed.

lemma ms_hash_binding_collision_condition_collision_categoryE
  (src : ms3a_bitness_layer_source) :
  ms_hash_binding_collision_condition
    (ms_hash_binding_semantic_state_of_category_source src
      BudgetParameters.MSHashBindingSemanticCollision).
proof.
rewrite /ms_hash_binding_collision_condition.
rewrite /ms_hash_binding_semantic_state_of_category_source /=.
rewrite /ms_hash_binding_collision_witness_of_category_source.
rewrite /ms_hash_binding_malformed_binding_witness_of_category_source.
rewrite /ms_hash_binding_expected_transcript_digest_of_source.
rewrite /ms_hash_binding_observed_digest_of_category_source.
rewrite /ms_hash_binding_observable_of_source_digest.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
by rewrite /pred1 /=.
qed.

lemma ms_hash_binding_malformed_binding_condition_malformed_binding_categoryE
  (src : ms3a_bitness_layer_source) :
  ms_hash_binding_malformed_binding_condition
    (ms_hash_binding_semantic_state_of_category_source src
      BudgetParameters.MSHashBindingSemanticMalformedBinding).
proof.
rewrite /ms_hash_binding_malformed_binding_condition.
rewrite /ms_hash_binding_semantic_state_of_category_source /=.
rewrite /ms_hash_binding_collision_witness_of_category_source.
rewrite /ms_hash_binding_malformed_binding_witness_of_category_source.
rewrite /ms_hash_binding_expected_transcript_digest_of_source.
rewrite /ms_hash_binding_observed_digest_of_category_source.
rewrite /ms_hash_binding_observable_of_source_digest.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
by rewrite /pred1 /=.
qed.

lemma ms_hash_binding_transcript_mismatch_condition_transcript_mismatch_categoryE
  (src : ms3a_bitness_layer_source) :
  ms_hash_binding_transcript_mismatch_condition
    (ms_hash_binding_semantic_state_of_category_source src
      BudgetParameters.MSHashBindingSemanticTranscriptMismatch).
proof.
rewrite /ms_hash_binding_transcript_mismatch_condition.
rewrite /ms_hash_binding_semantic_state_of_category_source /=.
rewrite /ms_hash_binding_collision_witness_of_category_source.
rewrite /ms_hash_binding_malformed_binding_witness_of_category_source.
rewrite /ms_hash_binding_observed_digest_of_category_source.
rewrite /ms_hash_binding_observable_of_source_digest.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
by rewrite /pred1 /=.
qed.

lemma ms_hash_binding_semantic_category_condition_stateE
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_semantic_category_condition category
    (ms_hash_binding_semantic_state_of_category_source src category).
proof.
case: category=> /=.
- exact (ms_hash_binding_clean_condition_clean_categoryE src).
- exact (ms_hash_binding_collision_condition_collision_categoryE src).
- exact (ms_hash_binding_malformed_binding_condition_malformed_binding_categoryE src).
exact (ms_hash_binding_transcript_mismatch_condition_transcript_mismatch_categoryE src).
qed.

op ms_hash_binding_semantic_slot_support : int list =
  range 0 BudgetParameters.ms_hash_binding_total_slot_count.

lemma ms_hash_binding_semantic_slot_supportE :
  ms_hash_binding_semantic_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /ms_hash_binding_semantic_slot_support.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form.
rewrite (range_ltn 0 16) 1:/# /=.
rewrite (range_ltn 1 16) 1:/# /=.
rewrite (range_ltn 2 16) 1:/# /=.
rewrite (range_ltn 3 16) 1:/# /=.
rewrite (range_ltn 4 16) 1:/# /=.
rewrite (range_ltn 5 16) 1:/# /=.
rewrite (range_ltn 6 16) 1:/# /=.
rewrite (range_ltn 7 16) 1:/# /=.
rewrite (range_ltn 8 16) 1:/# /=.
rewrite (range_ltn 9 16) 1:/# /=.
rewrite (range_ltn 10 16) 1:/# /=.
rewrite (range_ltn 11 16) 1:/# /=.
rewrite (range_ltn 12 16) 1:/# /=.
rewrite (range_ltn 13 16) 1:/# /=.
rewrite (range_ltn 14 16) 1:/# /=.
rewrite (range_ltn 15 16) 1:/# /=.
by rewrite range_geq /=.
qed.

lemma ms_hash_binding_semantic_slot_support_uniq :
  uniq ms_hash_binding_semantic_slot_support.
proof. by rewrite /ms_hash_binding_semantic_slot_support range_uniq. qed.

op ms_hash_binding_semantic_category_of_slot
  (slot : int) : BudgetParameters.ms_hash_binding_semantic_category =
  if slot < BudgetParameters.ms_hash_binding_collision_slot_count then
    BudgetParameters.MSHashBindingSemanticCollision
  else if slot <
      BudgetParameters.ms_hash_binding_collision_slot_count +
      BudgetParameters.ms_hash_binding_malformed_binding_slot_count then
    BudgetParameters.MSHashBindingSemanticMalformedBinding
  else if slot < BudgetParameters.ms_hash_binding_failure_slot_count then
    BudgetParameters.MSHashBindingSemanticTranscriptMismatch
  else BudgetParameters.MSHashBindingSemanticClean.

op ms_hash_binding_semantic_bad_slot (slot : int) : bool =
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
    (ms_hash_binding_semantic_category_of_slot slot).

op d_ms_hash_binding_semantic_slot_choice : int distr =
  duniform ms_hash_binding_semantic_slot_support.

op d_ms_hash_binding_semantic_category_choice :
  BudgetParameters.ms_hash_binding_semantic_category distr =
  dmap d_ms_hash_binding_semantic_slot_choice
    ms_hash_binding_semantic_category_of_slot.

op d_ms_hash_binding_semantic_failure_choice : bool distr =
  dmap d_ms_hash_binding_semantic_category_choice
    BudgetParameters.ms_hash_binding_semantic_category_is_failure.

lemma ms_hash_binding_semantic_slot_choice_lossless :
  is_lossless d_ms_hash_binding_semantic_slot_choice.
proof.
rewrite /d_ms_hash_binding_semantic_slot_choice.
rewrite ms_hash_binding_semantic_slot_supportE.
by apply duniform_ll.
qed.

lemma d_ms_hash_binding_semantic_failure_choiceE :
  d_ms_hash_binding_semantic_failure_choice =
  dmap d_ms_hash_binding_semantic_slot_choice ms_hash_binding_semantic_bad_slot.
proof.
rewrite /d_ms_hash_binding_semantic_failure_choice.
rewrite /d_ms_hash_binding_semantic_category_choice.
rewrite (dmap_comp ms_hash_binding_semantic_category_of_slot
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
  d_ms_hash_binding_semantic_slot_choice).
have Hmap :
  dmap d_ms_hash_binding_semantic_slot_choice
    (BudgetParameters.ms_hash_binding_semantic_category_is_failure \o
      ms_hash_binding_semantic_category_of_slot) =
  dmap d_ms_hash_binding_semantic_slot_choice ms_hash_binding_semantic_bad_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /ms_hash_binding_semantic_bad_slot /(\o).
rewrite Hmap.
by [].
qed.

lemma ms_hash_binding_semantic_failure_choice_mass_true :
  mu1 d_ms_hash_binding_semantic_failure_choice true =
  BudgetParameters.ms_hash_binding_failure_slot_count%r /
  BudgetParameters.ms_hash_binding_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_hash_binding_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_hash_binding_semantic_slot_choice duniformE.
rewrite undup_id ?ms_hash_binding_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o ms_hash_binding_semantic_bad_slot)
      ms_hash_binding_semantic_slot_support = 3.
  by rewrite ms_hash_binding_semantic_slot_supportE
    /ms_hash_binding_semantic_bad_slot
    /BudgetParameters.ms_hash_binding_semantic_category_is_failure
    /ms_hash_binding_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_hash_binding_collision_slot_count
    /BudgetParameters.ms_hash_binding_malformed_binding_slot_count
    /BudgetParameters.ms_hash_binding_transcript_mismatch_slot_count
    /BudgetParameters.ms_hash_binding_failure_slot_count /=.
rewrite Hcount ms_hash_binding_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_hash_binding_failure_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_hash_binding_total_slot_count_demo_closed_form /=.
by smt().
qed.

op ms_hash_binding_local_failure_mass : real =
  mu1 d_ms_hash_binding_semantic_failure_choice true.

lemma ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic :
  ms_hash_binding_local_failure_mass =
  BudgetParameters.epsilon_ms_hash_binding_semantic.
proof.
rewrite /ms_hash_binding_local_failure_mass.
rewrite ms_hash_binding_semantic_failure_choice_mass_true.
rewrite BudgetParameters.epsilon_ms_hash_binding_semantic_closed_form.
by [].
qed.

lemma ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_semantic :
  ms_hash_binding_local_failure_mass <=
  BudgetParameters.epsilon_ms_hash_binding_semantic.
proof.
rewrite ms_hash_binding_local_failure_mass_eq_epsilon_ms_hash_binding_semantic.
by [].
qed.

lemma d_ms3a_bitness_real_source_canonical
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
  /ms3a_bitness_layer_source_of_real_payload /ms3a_canonical_public_source
  /ms3a_make_real_source /(\o) /=.
qed.

lemma d_ms3a_bitness_real_source_lossless
  (x : ms_public_input) :
  is_lossless (d_ms3a_bitness_real_source x).
proof.
rewrite d_ms3a_bitness_real_source_canonical.
by apply dunit_ll.
qed.

op d_ms_hash_binding_semantic_coupled_state
  (x : ms_public_input) : ms_hash_binding_semantic_state distr =
  dmap ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)
    (fun (p : ms3a_bitness_layer_source * BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p)).

op d_ms_hash_binding_public_semantic_observable_v2
  (x : ms_public_input) : ms_v2_transcript_observable distr =
  dmap (d_ms_hash_binding_semantic_coupled_state x)
    (fun (st : ms_hash_binding_semantic_state) => st.`mshbss_observed_observable).

op ms_hash_binding_semantic_failure_event
  (st : ms_hash_binding_semantic_state) : bool =
  BudgetParameters.ms_hash_binding_semantic_category_is_failure st.`mshbss_category.

op d_ms_hash_binding_semantic_failure_state_choice
  (x : ms_public_input) : bool distr =
  dmap (d_ms_hash_binding_semantic_coupled_state x)
    ms_hash_binding_semantic_failure_event.

op ms_hash_binding_execution_owned_semantic_failure_probability
  (x : ms_public_input) : real =
  mu1 (d_ms_hash_binding_semantic_failure_state_choice x) true.

lemma ms_hash_binding_dmap_dprod_snd_lossless ['a 'b]
  (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw : weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma d_ms_hash_binding_semantic_failure_state_choiceE
  (x : ms_public_input) :
  d_ms_hash_binding_semantic_failure_state_choice x =
  d_ms_hash_binding_semantic_failure_choice.
proof.
rewrite /d_ms_hash_binding_semantic_failure_state_choice
        /d_ms_hash_binding_semantic_coupled_state.
rewrite (dmap_comp
  (fun (p : ms3a_bitness_layer_source * BudgetParameters.ms_hash_binding_semantic_category) =>
     ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
  ms_hash_binding_semantic_failure_event
  ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)).
have Hmap :
  dmap ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)
    (ms_hash_binding_semantic_failure_event \o
      (fun (p : ms3a_bitness_layer_source * BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) =
  dmap ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)
    (fun (p : ms3a_bitness_layer_source * BudgetParameters.ms_hash_binding_semantic_category) =>
       BudgetParameters.ms_hash_binding_semantic_category_is_failure (snd p)).
  apply eq_dmap_in=> p _ /=.
  by rewrite /(\o) /ms_hash_binding_semantic_failure_event
    /ms_hash_binding_semantic_state_of_category_source /=.
rewrite Hmap.
rewrite -(dmap_comp snd BudgetParameters.ms_hash_binding_semantic_category_is_failure
  ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)).
have Hsnd :
  dmap ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice) snd =
  d_ms_hash_binding_semantic_category_choice.
  exact (ms_hash_binding_dmap_dprod_snd_lossless
    (d_ms3a_bitness_real_source x) d_ms_hash_binding_semantic_category_choice
    (d_ms3a_bitness_real_source_lossless x)).
rewrite Hsnd.
by rewrite /d_ms_hash_binding_semantic_failure_choice.
qed.

lemma ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_semantic_failure_probability x =
  ms_hash_binding_local_failure_mass.
proof.
rewrite /ms_hash_binding_execution_owned_semantic_failure_probability.
rewrite /ms_hash_binding_local_failure_mass.
by rewrite d_ms_hash_binding_semantic_failure_state_choiceE.
qed.

lemma ms_hash_binding_public_observable_divergence_implies_semantic_failure
  (src : ms3a_bitness_layer_source)
  (category : BudgetParameters.ms_hash_binding_semantic_category) :
  ms_hash_binding_public_observable_divergence_condition
    (ms_hash_binding_semantic_state_of_category_source src category) =>
  ms_hash_binding_semantic_failure_event
    (ms_hash_binding_semantic_state_of_category_source src category).
proof.
case: category=> /=.
- rewrite /ms_hash_binding_public_observable_divergence_condition.
  rewrite /ms_hash_binding_semantic_failure_event.
  rewrite /ms_hash_binding_semantic_state_of_category_source /=.
  rewrite /ms_hash_binding_observed_digest_of_category_source.
  rewrite /ms_hash_binding_observable_of_source_digest.
  rewrite /ms3a_after_binding_observable_of_source.
  rewrite /ms_hash_binding_expected_transcript_digest_of_source.
  rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable /=.
  by rewrite /BudgetParameters.ms_hash_binding_semantic_category_is_failure /pred1.
- rewrite /ms_hash_binding_semantic_failure_event.
  rewrite /ms_hash_binding_semantic_state_of_category_source /=.
  by rewrite /BudgetParameters.ms_hash_binding_semantic_category_is_failure /pred1.
- rewrite /ms_hash_binding_semantic_failure_event.
  rewrite /ms_hash_binding_semantic_state_of_category_source /=.
  by rewrite /BudgetParameters.ms_hash_binding_semantic_category_is_failure /pred1.
rewrite /ms_hash_binding_semantic_failure_event.
rewrite /ms_hash_binding_semantic_state_of_category_source /=.
by rewrite /BudgetParameters.ms_hash_binding_semantic_category_is_failure /pred1.
qed.

lemma ms_hash_binding_public_observable_divergence_mass_le_execution_owned_semantic_failure
  (x : ms_public_input) :
  mu (d_ms_hash_binding_semantic_coupled_state x)
    ms_hash_binding_public_observable_divergence_condition <=
  ms_hash_binding_execution_owned_semantic_failure_probability x.
proof.
rewrite /d_ms_hash_binding_semantic_coupled_state.
rewrite /ms_hash_binding_execution_owned_semantic_failure_probability.
rewrite /d_ms_hash_binding_semantic_failure_state_choice.
rewrite /mu1 !dmapE /=.
have Hmu1 :
    mu ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)
      ((pred1 true \o ms_hash_binding_semantic_failure_event) \o
        (fun (p : ms3a_bitness_layer_source *
                   BudgetParameters.ms_hash_binding_semantic_category) =>
           ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) =
    mu ((d_ms3a_bitness_real_source x) `*` d_ms_hash_binding_semantic_category_choice)
      (ms_hash_binding_semantic_failure_event \o
        (fun (p : ms3a_bitness_layer_source *
                   BudgetParameters.ms_hash_binding_semantic_category) =>
           ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
  apply/mu_eq=> p /=.
  rewrite /(\o) /=.
  by case: (ms_hash_binding_semantic_failure_event
    (ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))).
rewrite Hmu1.
apply mu_sub => p /=.
exact (ms_hash_binding_public_observable_divergence_implies_semantic_failure
  (fst p) (snd p)).
qed.

lemma A_MS1_hash_binding_execution_owned_semantic_bound
  (x : ms_public_input) :
  ms_hash_binding_execution_owned_semantic_failure_probability x <=
  BudgetParameters.epsilon_ms_hash_binding_semantic.
proof.
rewrite ms_hash_binding_execution_owned_semantic_failure_probability_eq_local_mass.
exact ms_hash_binding_local_failure_mass_le_epsilon_ms_hash_binding_semantic.
qed.