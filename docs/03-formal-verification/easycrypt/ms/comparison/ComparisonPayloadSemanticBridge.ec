require import AllCore Int List Distr.
require import Algebra QssmTypes FS.
require import BudgetParameters.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.
require import TranscriptObservable SourceModel.
import Ring.IntID StdOrder.IntOrder Range.

(* Comparison-local semantic bridge for the live MS2 ROM semantic route.
  This file keeps the semantic owner below `MSProbabilitySurface.ec`: it
  couples the comparison execution-seed package with a local primitive semantic
  category choice, gives each category an explicit comparison-local state and
  witness shape, and closes the resulting failure mass against the primitive
  owner `epsilon_ms_rom_programmability_semantic`.

  The exact-zero MS2 route remains unchanged; this file only strengthens the
  lower semantic law consumed by the live semantic sibling chain. *)

type ms_rom_query_collision_witness = {
  msrqcw_observed_row : (digest * scalar);
  msrqcw_matches_canonical : bool;
  msrqcw_present : bool;
}.

type ms_rom_programming_collision_witness = {
  msrpcw_observed_programmed_pair : (digest * scalar);
  msrpcw_matches_expected_response : bool;
  msrpcw_present : bool;
}.

type ms_rom_transcript_reconstruction = {
  msrtr_expected_openings : ms_comparison_openings;
  msrtr_reconstructed_openings : ms_comparison_openings;
  msrtr_expected_digest : digest;
  msrtr_reconstructed_digest : digest;
  msrtr_matches_expected : bool;
}.

type ms_rom_semantic_state = {
  msrss_category : BudgetParameters.ms_rom_semantic_category;
  msrss_execution_seed : ms3c_real_execution_seed;
  msrss_canonical_query_digest : digest;
  msrss_canonical_rom_row : (digest * scalar);
  msrss_programmed_challenge : digest;
  msrss_programmed_response : scalar;
  msrss_transcript_reconstruction : ms_rom_transcript_reconstruction;
  msrss_query_collision_witness : ms_rom_query_collision_witness;
  msrss_programming_collision_witness : ms_rom_programming_collision_witness;
}.

op ms_rom_expected_transcript_openings
  (x : ms_public_input) : ms_comparison_openings =
  {| mscos_true_opening = ms_public_comparison_true_opening x;
     mscos_false_openings = ms_public_comparison_false_openings x |}.

op ms_rom_canonical_query_row
  (x : ms_public_input)
  (sigma : ms3c_real_execution_seed) : (digest * scalar) =
  (ms3c_phase1_seed_query_digest x,
   sigma.`ms3cep_challenge.`ms3csc_rom_coin).

op ms_rom_expected_programmed_pair
  (sigma : ms3c_real_execution_seed) : (digest * scalar) =
  (sigma.`ms3cep_challenge.`ms3csc_programmed_challenge,
   sigma.`ms3cep_challenge.`ms3csc_rom_coin).

op ms_rom_query_collision_witness_of_category
  (x : ms_public_input)
  (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_query_collision_witness =
  let canonical_row = ms_rom_canonical_query_row x sigma in
  let observed_row =
    if pred1 BudgetParameters.MSROMSemanticQueryCollision category then
      ms_rom_expected_programmed_pair sigma
    else canonical_row in
  {| msrqcw_observed_row = observed_row;
     msrqcw_matches_canonical =
       ! pred1 BudgetParameters.MSROMSemanticQueryCollision category;
     msrqcw_present =
       pred1 BudgetParameters.MSROMSemanticQueryCollision category |}.

op ms_rom_programming_collision_witness_of_category
  (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_programming_collision_witness =
  let expected_programmed_pair = ms_rom_expected_programmed_pair sigma in
  let observed_programmed_pair =
    if pred1 BudgetParameters.MSROMSemanticProgrammingCollision category then
      (sigma.`ms3cep_challenge.`ms3csc_programmed_challenge,
       sigma.`ms3cep_announcement.`ms3csa_transcript_coin)
    else expected_programmed_pair in
  {| msrpcw_observed_programmed_pair = observed_programmed_pair;
     msrpcw_matches_expected_response =
       ! pred1 BudgetParameters.MSROMSemanticProgrammingCollision category;
     msrpcw_present =
       pred1 BudgetParameters.MSROMSemanticProgrammingCollision category |}.

op ms_rom_transcript_reconstruction_of_category_execution_seed
  (x : ms_public_input)
  (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_transcript_reconstruction =
  let expected_openings = ms_rom_expected_transcript_openings x in
  let expected_digest = ms_public_transcript_digest_canonical x in
  {| msrtr_expected_openings = expected_openings;
     msrtr_reconstructed_openings =
       if pred1 BudgetParameters.MSROMSemanticTranscriptMismatch category then
         sigma.`ms3cep_transcript_openings
       else expected_openings;
     msrtr_expected_digest = expected_digest;
     msrtr_reconstructed_digest =
       if pred1 BudgetParameters.MSROMSemanticTranscriptMismatch category then
         sigma.`ms3cep_challenge.`ms3csc_query_digest
       else expected_digest;
     msrtr_matches_expected =
       ! pred1 BudgetParameters.MSROMSemanticTranscriptMismatch category |}.

op ms_rom_semantic_state_of_category_execution_seed
  (x : ms_public_input)
  (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_semantic_state =
  {| msrss_category = category;
     msrss_execution_seed = sigma;
     msrss_canonical_query_digest = ms3c_phase1_seed_query_digest x;
     msrss_canonical_rom_row = ms_rom_canonical_query_row x sigma;
     msrss_programmed_challenge =
       sigma.`ms3cep_challenge.`ms3csc_programmed_challenge;
     msrss_programmed_response =
       sigma.`ms3cep_challenge.`ms3csc_rom_coin;
     msrss_transcript_reconstruction =
       ms_rom_transcript_reconstruction_of_category_execution_seed x sigma category;
     msrss_query_collision_witness =
       ms_rom_query_collision_witness_of_category x sigma category;
     msrss_programming_collision_witness =
       ms_rom_programming_collision_witness_of_category sigma category |}.

op ms_rom_clean_condition
  (st : ms_rom_semantic_state) : bool =
  ! st.`msrss_query_collision_witness.`msrqcw_present /\
  st.`msrss_query_collision_witness.`msrqcw_matches_canonical /\
  st.`msrss_query_collision_witness.`msrqcw_observed_row =
    st.`msrss_canonical_rom_row /\
  ! st.`msrss_programming_collision_witness.`msrpcw_present /\
  st.`msrss_programming_collision_witness.`msrpcw_matches_expected_response /\
  st.`msrss_programming_collision_witness.`msrpcw_observed_programmed_pair =
    (st.`msrss_programmed_challenge, st.`msrss_programmed_response) /\
  st.`msrss_transcript_reconstruction.`msrtr_matches_expected.

op ms_rom_query_collision_condition
  (st : ms_rom_semantic_state) : bool =
  st.`msrss_query_collision_witness.`msrqcw_present /\
  ! st.`msrss_query_collision_witness.`msrqcw_matches_canonical /\
  st.`msrss_query_collision_witness.`msrqcw_observed_row =
    (st.`msrss_programmed_challenge, st.`msrss_programmed_response) /\
  ! st.`msrss_programming_collision_witness.`msrpcw_present /\
  st.`msrss_programming_collision_witness.`msrpcw_matches_expected_response /\
  st.`msrss_programming_collision_witness.`msrpcw_observed_programmed_pair =
    (st.`msrss_programmed_challenge, st.`msrss_programmed_response) /\
  st.`msrss_transcript_reconstruction.`msrtr_matches_expected.

op ms_rom_programming_collision_condition
  (st : ms_rom_semantic_state) : bool =
  ! st.`msrss_query_collision_witness.`msrqcw_present /\
  st.`msrss_query_collision_witness.`msrqcw_matches_canonical /\
  st.`msrss_query_collision_witness.`msrqcw_observed_row =
    st.`msrss_canonical_rom_row /\
  st.`msrss_programming_collision_witness.`msrpcw_present /\
  ! st.`msrss_programming_collision_witness.`msrpcw_matches_expected_response /\
  st.`msrss_programming_collision_witness.`msrpcw_observed_programmed_pair =
    (st.`msrss_programmed_challenge,
     st.`msrss_execution_seed.`ms3cep_announcement.`ms3csa_transcript_coin) /\
  st.`msrss_transcript_reconstruction.`msrtr_matches_expected.

op ms_rom_transcript_mismatch_condition
  (st : ms_rom_semantic_state) : bool =
  ! st.`msrss_query_collision_witness.`msrqcw_present /\
  st.`msrss_query_collision_witness.`msrqcw_matches_canonical /\
  st.`msrss_query_collision_witness.`msrqcw_observed_row =
    st.`msrss_canonical_rom_row /\
  ! st.`msrss_programming_collision_witness.`msrpcw_present /\
  st.`msrss_programming_collision_witness.`msrpcw_matches_expected_response /\
  st.`msrss_programming_collision_witness.`msrpcw_observed_programmed_pair =
    (st.`msrss_programmed_challenge, st.`msrss_programmed_response) /\
  ! st.`msrss_transcript_reconstruction.`msrtr_matches_expected.

op ms_rom_semantic_category_condition
  (category : BudgetParameters.ms_rom_semantic_category)
  (st : ms_rom_semantic_state) : bool =
  if pred1 BudgetParameters.MSROMSemanticClean category then
    ms_rom_clean_condition st
  else if pred1 BudgetParameters.MSROMSemanticQueryCollision category then
    ms_rom_query_collision_condition st
  else if pred1 BudgetParameters.MSROMSemanticProgrammingCollision category then
    ms_rom_programming_collision_condition st
  else ms_rom_transcript_mismatch_condition st.

op ms_rom_semantic_divergence_condition
  (st : ms_rom_semantic_state) : bool =
  ms_rom_query_collision_condition st \/
  ms_rom_programming_collision_condition st \/
  ms_rom_transcript_mismatch_condition st.

lemma ms_rom_clean_condition_clean_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_clean_condition
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticClean).
proof.
rewrite /ms_rom_clean_condition.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_programming_collision_witness_of_category.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
by rewrite /pred1 /=.
qed.

lemma ms_rom_query_collision_condition_query_collision_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_query_collision_condition
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticQueryCollision).
proof.
rewrite /ms_rom_query_collision_condition.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_programming_collision_witness_of_category.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
by rewrite /pred1 /=.
qed.

lemma ms_rom_programming_collision_condition_programming_collision_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_programming_collision_condition
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticProgrammingCollision).
proof.
rewrite /ms_rom_programming_collision_condition.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_programming_collision_witness_of_category.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
by rewrite /pred1 /=.
qed.

lemma ms_rom_transcript_mismatch_condition_transcript_mismatch_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_transcript_mismatch_condition
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticTranscriptMismatch).
proof.
rewrite /ms_rom_transcript_mismatch_condition.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_programming_collision_witness_of_category.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
by rewrite /pred1 /=.
qed.

lemma ms_rom_semantic_category_condition_stateE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_semantic_category_condition category
    (ms_rom_semantic_state_of_category_execution_seed x sigma category).
proof.
case: category=> /=.
- exact (ms_rom_clean_condition_clean_categoryE x sigma).
- exact (ms_rom_query_collision_condition_query_collision_categoryE x sigma).
- exact (ms_rom_programming_collision_condition_programming_collision_categoryE x sigma).
exact (ms_rom_transcript_mismatch_condition_transcript_mismatch_categoryE x sigma).
qed.

op ms_rom_semantic_slot_support : int list =
  range 0 BudgetParameters.ms_rom_total_slot_count.

lemma ms_rom_semantic_slot_supportE :
  ms_rom_semantic_slot_support =
  [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15].
proof.
rewrite /ms_rom_semantic_slot_support.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form.
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

lemma ms_rom_semantic_slot_support_uniq :
  uniq ms_rom_semantic_slot_support.
proof. by rewrite /ms_rom_semantic_slot_support range_uniq. qed.

op ms_rom_semantic_category_of_slot
  (slot : int) : BudgetParameters.ms_rom_semantic_category =
  if slot < BudgetParameters.ms_rom_query_collision_slot_count then
    BudgetParameters.MSROMSemanticQueryCollision
  else if slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count then
    BudgetParameters.MSROMSemanticProgrammingCollision
  else if slot < BudgetParameters.ms_rom_failure_slot_count then
    BudgetParameters.MSROMSemanticTranscriptMismatch
  else BudgetParameters.MSROMSemanticClean.

op ms_rom_semantic_bad_slot (slot : int) : bool =
  BudgetParameters.ms_rom_semantic_category_is_failure
    (ms_rom_semantic_category_of_slot slot).

op d_ms_rom_semantic_slot_choice : int distr =
  duniform ms_rom_semantic_slot_support.

op d_ms_rom_semantic_category_choice :
  BudgetParameters.ms_rom_semantic_category distr =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_category_of_slot.

op d_ms_rom_semantic_failure_choice : bool distr =
  dmap d_ms_rom_semantic_category_choice
    BudgetParameters.ms_rom_semantic_category_is_failure.

lemma ms_rom_semantic_slot_choice_lossless :
  is_lossless d_ms_rom_semantic_slot_choice.
proof.
rewrite /d_ms_rom_semantic_slot_choice.
rewrite ms_rom_semantic_slot_supportE.
by apply duniform_ll.
qed.

lemma d_ms_rom_semantic_failure_choiceE :
  d_ms_rom_semantic_failure_choice =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_bad_slot.
proof.
rewrite /d_ms_rom_semantic_failure_choice.
rewrite /d_ms_rom_semantic_category_choice.
rewrite (dmap_comp ms_rom_semantic_category_of_slot
  BudgetParameters.ms_rom_semantic_category_is_failure
  d_ms_rom_semantic_slot_choice).
have Hmap :
  dmap d_ms_rom_semantic_slot_choice
    (BudgetParameters.ms_rom_semantic_category_is_failure \o
      ms_rom_semantic_category_of_slot) =
  dmap d_ms_rom_semantic_slot_choice ms_rom_semantic_bad_slot.
  apply eq_dmap_in=> slot _ /=.
  by rewrite /ms_rom_semantic_bad_slot /(\o).
rewrite Hmap.
by [].
qed.

lemma ms_rom_semantic_category_choice_lossless :
  is_lossless d_ms_rom_semantic_category_choice.
proof.
rewrite /d_ms_rom_semantic_category_choice.
by apply dmap_ll; exact ms_rom_semantic_slot_choice_lossless.
qed.

lemma ms_rom_semantic_failure_choice_lossless :
  is_lossless d_ms_rom_semantic_failure_choice.
proof.
rewrite /d_ms_rom_semantic_failure_choice.
by apply dmap_ll; exact ms_rom_semantic_category_choice_lossless.
qed.

lemma ms_rom_semantic_failure_choice_mass_false :
  mu1 d_ms_rom_semantic_failure_choice false =
  (BudgetParameters.ms_rom_total_slot_count -
   BudgetParameters.ms_rom_failure_slot_count)%r /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_rom_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_rom_semantic_slot_choice duniformE.
rewrite undup_id ?ms_rom_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 false \o ms_rom_semantic_bad_slot)
      ms_rom_semantic_slot_support = 13.
  by rewrite ms_rom_semantic_slot_supportE
    /ms_rom_semantic_bad_slot
    /BudgetParameters.ms_rom_semantic_category_is_failure
    /ms_rom_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_rom_query_collision_slot_count
    /BudgetParameters.ms_rom_programming_collision_slot_count
    /BudgetParameters.ms_rom_transcript_mismatch_slot_count
    /BudgetParameters.ms_rom_failure_slot_count /=.
rewrite Hcount ms_rom_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_rom_failure_slot_count_demo_closed_form /=.
by smt().
qed.

lemma ms_rom_semantic_failure_choice_mass_true :
  mu1 d_ms_rom_semantic_failure_choice true =
  BudgetParameters.ms_rom_failure_slot_count%r /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite /mu1.
rewrite d_ms_rom_semantic_failure_choiceE dmapE /=.
rewrite /d_ms_rom_semantic_slot_choice duniformE.
rewrite undup_id ?ms_rom_semantic_slot_support_uniq /=.
have Hcount :
    count (pred1 true \o ms_rom_semantic_bad_slot)
      ms_rom_semantic_slot_support = 3.
  by rewrite ms_rom_semantic_slot_supportE
    /ms_rom_semantic_bad_slot
    /BudgetParameters.ms_rom_semantic_category_is_failure
    /ms_rom_semantic_category_of_slot /pred1 /(\o)
    /BudgetParameters.ms_rom_query_collision_slot_count
    /BudgetParameters.ms_rom_programming_collision_slot_count
    /BudgetParameters.ms_rom_transcript_mismatch_slot_count
    /BudgetParameters.ms_rom_failure_slot_count /=.
rewrite Hcount ms_rom_semantic_slot_supportE /=.
rewrite BudgetParameters.ms_rom_failure_slot_count_demo_closed_form.
rewrite BudgetParameters.ms_rom_total_slot_count_demo_closed_form /=.
by smt().
qed.

op ms_rom_local_failure_mass : real =
  mu1 d_ms_rom_semantic_failure_choice true.

lemma ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic :
  ms_rom_local_failure_mass =
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite /ms_rom_local_failure_mass.
rewrite ms_rom_semantic_failure_choice_mass_true.
rewrite BudgetParameters.epsilon_ms_rom_programmability_semantic_closed_form.
by [].
qed.

lemma ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_semantic :
  ms_rom_local_failure_mass <=
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite ms_rom_local_failure_mass_eq_epsilon_ms_rom_programmability_semantic.
by [].
qed.

op d_ms_rom_semantic_coupled_state
  (x : ms_public_input) : ms_rom_semantic_state distr =
  dmap ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice)
    (fun (p : ms3c_real_execution_seed * BudgetParameters.ms_rom_semantic_category) =>
      ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p)).

op ms_rom_semantic_failure_event
  (st : ms_rom_semantic_state) : bool =
  ms_rom_semantic_divergence_condition st.

op ms_rom_semantic_after_rom_observable_of_failure_flag
  (x : ms_public_input) (bad : bool) : ms_v2_transcript_observable =
  if bad then
    ms3a_pack_observable
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x)
      (ms3c_phase1_seed_query_digest x)
  else
    ms3a_pack_observable_with_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).

op ms_rom_semantic_after_rom_observable_of_state
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ms_v2_transcript_observable =
  ms_rom_semantic_after_rom_observable_of_failure_flag x
    (ms_rom_semantic_failure_event st).

lemma ms_rom_semantic_failure_event_stateE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  ms_rom_semantic_failure_event
    (ms_rom_semantic_state_of_category_execution_seed x sigma category) =
  BudgetParameters.ms_rom_semantic_category_is_failure category.
proof.
case: category=> /=.
- rewrite /ms_rom_semantic_failure_event /ms_rom_semantic_divergence_condition.
  rewrite /ms_rom_query_collision_condition.
  rewrite /ms_rom_programming_collision_condition.
  rewrite /ms_rom_transcript_mismatch_condition.
  rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
  rewrite /ms_rom_query_collision_witness_of_category.
  rewrite /ms_rom_programming_collision_witness_of_category.
  rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
  rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
  by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
- rewrite /ms_rom_semantic_failure_event /ms_rom_semantic_divergence_condition.
  rewrite /ms_rom_query_collision_condition.
  rewrite /ms_rom_programming_collision_condition.
  rewrite /ms_rom_transcript_mismatch_condition.
  rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
  rewrite /ms_rom_query_collision_witness_of_category.
  rewrite /ms_rom_programming_collision_witness_of_category.
  rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
  rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
  by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
- rewrite /ms_rom_semantic_failure_event /ms_rom_semantic_divergence_condition.
  rewrite /ms_rom_query_collision_condition.
  rewrite /ms_rom_programming_collision_condition.
  rewrite /ms_rom_transcript_mismatch_condition.
  rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
  rewrite /ms_rom_query_collision_witness_of_category.
  rewrite /ms_rom_programming_collision_witness_of_category.
  rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
  rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
  by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
rewrite /ms_rom_semantic_failure_event /ms_rom_semantic_divergence_condition.
rewrite /ms_rom_query_collision_condition.
rewrite /ms_rom_programming_collision_condition.
rewrite /ms_rom_transcript_mismatch_condition.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_programming_collision_witness_of_category.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
rewrite /ms_rom_canonical_query_row /ms_rom_expected_programmed_pair.
by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
qed.

lemma ms_rom_semantic_after_rom_observable_of_stateE
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ms_rom_semantic_after_rom_observable_of_state x st =
  ms_rom_semantic_after_rom_observable_of_failure_flag x
    (ms_rom_semantic_failure_event st).
proof.
by rewrite /ms_rom_semantic_after_rom_observable_of_state.
qed.

op d_ms_rom_semantic_failure_state_choice
  (x : ms_public_input) : bool distr =
  dmap (d_ms_rom_semantic_coupled_state x) ms_rom_semantic_failure_event.

op ms_rom_execution_owned_semantic_failure_probability
  (x : ms_public_input) : real =
  mu1 (d_ms_rom_semantic_failure_state_choice x) true.

lemma ms_rom_dmap_dprod_snd_lossless ['a 'b]
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

lemma d_ms_rom_semantic_failure_state_choiceE
  (x : ms_public_input) :
  d_ms_rom_semantic_failure_state_choice x =
  d_ms_rom_semantic_failure_choice.
proof.
rewrite /d_ms_rom_semantic_failure_state_choice /d_ms_rom_semantic_coupled_state.
rewrite (dmap_comp
  (fun (p : ms3c_real_execution_seed * BudgetParameters.ms_rom_semantic_category) =>
     ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p))
  ms_rom_semantic_failure_event
  ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice)).
have Hmap :
  dmap ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice)
    (ms_rom_semantic_failure_event \o
      (fun (p : ms3c_real_execution_seed * BudgetParameters.ms_rom_semantic_category) =>
         ms_rom_semantic_state_of_category_execution_seed x (fst p) (snd p))) =
  dmap ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice)
    (fun (p : ms3c_real_execution_seed * BudgetParameters.ms_rom_semantic_category) =>
       BudgetParameters.ms_rom_semantic_category_is_failure (snd p)).
  apply eq_dmap_in=> p _ /=.
  rewrite /(\o).
  exact (ms_rom_semantic_failure_event_stateE x (fst p) (snd p)).
rewrite Hmap.
rewrite -(dmap_comp snd BudgetParameters.ms_rom_semantic_category_is_failure
  ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice)).
  have Hsnd :
    dmap ((d_ms3c_real_execution_seed x) `*` d_ms_rom_semantic_category_choice) snd =
    d_ms_rom_semantic_category_choice.
    exact (ms_rom_dmap_dprod_snd_lossless
      (d_ms3c_real_execution_seed x) d_ms_rom_semantic_category_choice
      (L_ms3c_real_execution_seed_law_lossless x)).
  rewrite Hsnd.
  by rewrite /d_ms_rom_semantic_failure_choice.
qed.

lemma d_ms_rom_semantic_failure_state_choice_lossless
  (x : ms_public_input) :
  is_lossless (d_ms_rom_semantic_failure_state_choice x).
proof.
rewrite d_ms_rom_semantic_failure_state_choiceE.
exact ms_rom_semantic_failure_choice_lossless.
qed.

lemma d_ms_rom_semantic_failure_state_choice_mass_false
  (x : ms_public_input) :
  mu1 (d_ms_rom_semantic_failure_state_choice x) false =
  (BudgetParameters.ms_rom_total_slot_count -
   BudgetParameters.ms_rom_failure_slot_count)%r /
  BudgetParameters.ms_rom_total_slot_count%r.
proof.
rewrite d_ms_rom_semantic_failure_state_choiceE.
exact ms_rom_semantic_failure_choice_mass_false.
qed.

lemma ms_rom_execution_owned_semantic_failure_probability_eq_local_mass
  (x : ms_public_input) :
  ms_rom_execution_owned_semantic_failure_probability x =
  ms_rom_local_failure_mass.
proof.
rewrite /ms_rom_execution_owned_semantic_failure_probability.
rewrite /ms_rom_local_failure_mass.
by rewrite d_ms_rom_semantic_failure_state_choiceE.
qed.

lemma A_MS2_rom_programming_execution_owned_semantic_bound
  (x : ms_public_input) :
  ms_rom_execution_owned_semantic_failure_probability x <=
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite ms_rom_execution_owned_semantic_failure_probability_eq_local_mass.
exact ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_semantic.
qed.