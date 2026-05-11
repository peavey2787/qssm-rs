require import AllCore Int List Distr.
require import QssmTypes.
require import SourceTypes.
require import TranscriptObservable.
require import BudgetParameters.
require import ParameterizedBudgetParameters.
require import ComparisonPayloadExecutionSeedTypes.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticSlotMassParameterized.
import Ring.IntID StdOrder.IntOrder Range.

(* Live parameterized MS2 execution-owned/public-observable core.
   This reuses the demo semantic state constructors, but swaps the semantic
   category sampler to the parameterized owner surface. *)

op d_ms_rom_semantic_category_choice_parameterized :
  BudgetParameters.ms_rom_semantic_category distr =
  dmap d_ms_rom_semantic_slot_choice_parameterized
    ms_rom_semantic_category_of_slot_parameterized.

lemma d_ms_rom_semantic_category_choice_parameterized_lossless :
  is_lossless d_ms_rom_semantic_category_choice_parameterized.
proof.
rewrite /d_ms_rom_semantic_category_choice_parameterized.
apply dmap_ll.
rewrite /d_ms_rom_semantic_slot_choice_parameterized.
apply drange_ll.
exact ParameterizedBudgetParameters.ms2_param_total_count_pos.
qed.

op d_ms_rom_semantic_coupled_state_parameterized
  (x : ms_public_input) : ms_rom_semantic_state distr =
  dmap ((d_ms3c_real_execution_seed x) `*`
        d_ms_rom_semantic_category_choice_parameterized)
    (fun (p : ms3c_real_execution_seed *
              BudgetParameters.ms_rom_semantic_category) =>
      ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p)).

lemma d_ms_rom_semantic_coupled_state_parameterized_lossless
  (x : ms_public_input) :
  is_lossless (d_ms_rom_semantic_coupled_state_parameterized x).
proof.
rewrite /d_ms_rom_semantic_coupled_state_parameterized.
apply dmap_ll.
apply dprod_ll_auto.
- exact (L_ms3c_real_execution_seed_law_lossless x).
exact d_ms_rom_semantic_category_choice_parameterized_lossless.
qed.

op d_ms_after_rom_public_semantic_observable_v2_live_parameterized
  (x : ms_public_input) : ms_v2_transcript_observable distr =
  dmap (d_ms_rom_semantic_coupled_state_parameterized x)
    (ms_after_rom_public_semantic_observable_of_state x).

op d_ms_rom_semantic_failure_state_choice_parameterized
  (x : ms_public_input) : bool distr =
  dmap (d_ms_rom_semantic_coupled_state_parameterized x)
    ms_rom_semantic_failure_event.

lemma d_ms_rom_semantic_failure_state_choice_parameterizedE
  (x : ms_public_input) :
  d_ms_rom_semantic_failure_state_choice_parameterized x =
  d_ms_rom_semantic_failure_choice_parameterized.
proof.
rewrite /d_ms_rom_semantic_failure_state_choice_parameterized
        /d_ms_rom_semantic_coupled_state_parameterized.
rewrite (dmap_comp
  (fun (p : ms3c_real_execution_seed *
             BudgetParameters.ms_rom_semantic_category) =>
     ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p))
  ms_rom_semantic_failure_event
  ((d_ms3c_real_execution_seed x) `*`
   d_ms_rom_semantic_category_choice_parameterized)).
have Hmap :
  dmap ((d_ms3c_real_execution_seed x) `*`
        d_ms_rom_semantic_category_choice_parameterized)
    (ms_rom_semantic_failure_event \o
      (fun (p : ms3c_real_execution_seed *
                 BudgetParameters.ms_rom_semantic_category) =>
         ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p))) =
  dmap ((d_ms3c_real_execution_seed x) `*`
        d_ms_rom_semantic_category_choice_parameterized)
    (fun (p : ms3c_real_execution_seed *
               BudgetParameters.ms_rom_semantic_category) =>
       BudgetParameters.ms_rom_semantic_category_is_failure (snd p)).
  apply eq_dmap_in=> p _ /=.
  rewrite /(\o).
  exact (ms_rom_semantic_failure_event_stateE x (fst p) (snd p)).
rewrite Hmap.
rewrite -(dmap_comp snd BudgetParameters.ms_rom_semantic_category_is_failure
  ((d_ms3c_real_execution_seed x) `*`
   d_ms_rom_semantic_category_choice_parameterized)).
have Hsnd :
  dmap ((d_ms3c_real_execution_seed x) `*`
        d_ms_rom_semantic_category_choice_parameterized) snd =
  d_ms_rom_semantic_category_choice_parameterized.
  exact (ms_rom_dmap_dprod_snd_lossless
    (d_ms3c_real_execution_seed x)
    d_ms_rom_semantic_category_choice_parameterized
    (L_ms3c_real_execution_seed_law_lossless x)).
rewrite Hsnd.
rewrite /d_ms_rom_semantic_category_choice_parameterized.
rewrite (dmap_comp
  ms_rom_semantic_category_of_slot_parameterized
  BudgetParameters.ms_rom_semantic_category_is_failure
  d_ms_rom_semantic_slot_choice_parameterized).
have Hbad :
  dmap d_ms_rom_semantic_slot_choice_parameterized
    (BudgetParameters.ms_rom_semantic_category_is_failure \o
      ms_rom_semantic_category_of_slot_parameterized) =
  d_ms_rom_semantic_failure_choice_parameterized.
  rewrite /d_ms_rom_semantic_failure_choice_parameterized.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /(\o) /ms_rom_semantic_bad_slot_parameterized.
by rewrite Hbad.
qed.