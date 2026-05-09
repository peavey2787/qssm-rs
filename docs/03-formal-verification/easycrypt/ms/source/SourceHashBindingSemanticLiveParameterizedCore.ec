require import AllCore Int List Distr.
require import QssmTypes.
require import BudgetParameters.
require import TranscriptObservable.
require import SourceTypes SourceModel.
require import SourceConstructors SourcePayloadDistributions.
require import SourceBitnessDistributions SourceObservableDistributions.
require import SourceHashBindingSemanticBridge.
require import SourceHashBindingSemanticSlotMassParameterized.
import Ring.IntID StdOrder.IntOrder Range.

(* Live parameterized MS1 canonical failure core.
   This reuses the source/state constructors from the demo semantic bridge, but
   swaps the semantic category sampler to the parameterized owner surface. *)

op d_ms_hash_binding_semantic_category_choice_parameterized :
  BudgetParameters.ms_hash_binding_semantic_category distr =
  dmap d_ms_hash_binding_semantic_slot_choice_parameterized
    ms_hash_binding_semantic_category_of_slot_parameterized.

op d_ms_hash_binding_semantic_coupled_state_parameterized
  (x : ms_public_input) : ms_hash_binding_semantic_state distr =
  dmap ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
    (fun (p : ms3a_bitness_layer_source *
              BudgetParameters.ms_hash_binding_semantic_category) =>
      ms_hash_binding_semantic_state_of_category_source (fst p) (snd p)).

op d_ms_hash_binding_semantic_failure_state_choice_parameterized
  (x : ms_public_input) : bool distr =
  dmap (d_ms_hash_binding_semantic_coupled_state_parameterized x)
    ms_hash_binding_semantic_failure_event.

lemma d_ms_hash_binding_semantic_failure_state_choice_parameterizedE
  (x : ms_public_input) :
  d_ms_hash_binding_semantic_failure_state_choice_parameterized x =
  d_ms_hash_binding_semantic_failure_choice_parameterized.
proof.
rewrite /d_ms_hash_binding_semantic_failure_state_choice_parameterized
        /d_ms_hash_binding_semantic_coupled_state_parameterized.
rewrite (dmap_comp
  (fun (p : ms3a_bitness_layer_source *
             BudgetParameters.ms_hash_binding_semantic_category) =>
     ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))
  ms_hash_binding_semantic_failure_event
  ((d_ms3a_bitness_real_source x) `*`
   d_ms_hash_binding_semantic_category_choice_parameterized)).
have Hmap :
  dmap ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
    (ms_hash_binding_semantic_failure_event \o
      (fun (p : ms3a_bitness_layer_source *
                 BudgetParameters.ms_hash_binding_semantic_category) =>
         ms_hash_binding_semantic_state_of_category_source (fst p) (snd p))) =
  dmap ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized)
    (fun (p : ms3a_bitness_layer_source *
               BudgetParameters.ms_hash_binding_semantic_category) =>
       BudgetParameters.ms_hash_binding_semantic_category_is_failure (snd p)).
  apply eq_dmap_in=> p _ /=.
  by rewrite /(\o) /ms_hash_binding_semantic_failure_event
    /ms_hash_binding_semantic_state_of_category_source /=.
rewrite Hmap.
rewrite -(dmap_comp snd BudgetParameters.ms_hash_binding_semantic_category_is_failure
  ((d_ms3a_bitness_real_source x) `*`
   d_ms_hash_binding_semantic_category_choice_parameterized)).
have Hsnd :
  dmap ((d_ms3a_bitness_real_source x) `*`
        d_ms_hash_binding_semantic_category_choice_parameterized) snd =
  d_ms_hash_binding_semantic_category_choice_parameterized.
  exact (ms_hash_binding_dmap_dprod_snd_lossless
    (d_ms3a_bitness_real_source x)
    d_ms_hash_binding_semantic_category_choice_parameterized
    (d_ms3a_bitness_real_source_lossless x)).
rewrite Hsnd.
rewrite /d_ms_hash_binding_semantic_category_choice_parameterized.
rewrite (dmap_comp
  ms_hash_binding_semantic_category_of_slot_parameterized
  BudgetParameters.ms_hash_binding_semantic_category_is_failure
  d_ms_hash_binding_semantic_slot_choice_parameterized).
have Hbad :
  dmap d_ms_hash_binding_semantic_slot_choice_parameterized
    (BudgetParameters.ms_hash_binding_semantic_category_is_failure \o
      ms_hash_binding_semantic_category_of_slot_parameterized) =
  d_ms_hash_binding_semantic_failure_choice_parameterized.
  rewrite /d_ms_hash_binding_semantic_failure_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /(\o) /ms_hash_binding_semantic_bad_slot_parameterized.
by rewrite Hbad.
qed.