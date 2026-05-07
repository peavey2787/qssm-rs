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

lemma d_ms_rom_semantic_coupled_state_lossless
  (x : ms_public_input) :
  is_lossless (d_ms_rom_semantic_coupled_state x).
proof.
rewrite /d_ms_rom_semantic_coupled_state.
apply dmap_ll.
apply dprod_ll_auto.
- exact (L_ms3c_real_execution_seed_law_lossless x).
exact ms_rom_semantic_category_choice_lossless.
qed.

op ms_rom_semantic_failure_event
  (st : ms_rom_semantic_state) : bool =
  ms_rom_semantic_divergence_condition st.

op ms_after_rom_public_semantic_digest_of_state
  (x : ms_public_input) (st : ms_rom_semantic_state) : digest =
  if ms_rom_semantic_failure_event st then
    if pred1 BudgetParameters.MSROMSemanticQueryCollision st.`msrss_category then
      fst st.`msrss_query_collision_witness.`msrqcw_observed_row
    else if pred1 BudgetParameters.MSROMSemanticProgrammingCollision st.`msrss_category then
      fst st.`msrss_programming_collision_witness.`msrpcw_observed_programmed_pair
    else if pred1 BudgetParameters.MSROMSemanticTranscriptMismatch st.`msrss_category then
      st.`msrss_transcript_reconstruction.`msrtr_reconstructed_digest
    else
      ms_public_transcript_digest_canonical x
  else
    ms_public_transcript_digest_canonical x.

op ms_after_rom_public_semantic_observable_of_state
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ms_v2_transcript_observable =
  if ms_rom_semantic_failure_event st then
    ms3a_pack_observable
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x)
      (ms_after_rom_public_semantic_digest_of_state x st)
  else
    ms3a_pack_observable_with_digest
      (ms3a_public_stmt_digest x)
      (ms3a_public_result_bit x)
      (ms3a_public_bitness_globals x)
      (ms3a_public_comparison_global x).

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

op ms_rom_public_observable_divergence_condition
  (x : ms_public_input) (st : ms_rom_semantic_state) : bool =
  ms_after_rom_public_semantic_digest_of_state x st <>
  ms_public_transcript_digest_canonical x.

op ms_rom_public_divergence_global_digest_flag
  (x : ms_public_input) : bool =
  x.`mspi_comparison_global <>
  ms_public_transcript_digest_canonical x.

op ms_rom_public_divergence_query_digest_flag
  (x : ms_public_input) : bool =
  ms3c_phase1_seed_query_digest x <>
  ms_public_transcript_digest_canonical x.

op ms_rom_public_divergence_flag_of_category
  (x : ms_public_input) (category : BudgetParameters.ms_rom_semantic_category) : bool =
  if pred1 BudgetParameters.MSROMSemanticQueryCollision category then
    ms_rom_public_divergence_global_digest_flag x
  else if pred1 BudgetParameters.MSROMSemanticProgrammingCollision category then
    ms_rom_public_divergence_global_digest_flag x
  else if pred1 BudgetParameters.MSROMSemanticTranscriptMismatch category then
    ms_rom_public_divergence_query_digest_flag x
  else false.

op ms_rom_public_silent_failure_category
  (x : ms_public_input) (category : BudgetParameters.ms_rom_semantic_category) : bool =
  BudgetParameters.ms_rom_semantic_category_is_failure category /\
  ! ms_rom_public_divergence_flag_of_category x category.

lemma ms_rom_semantic_after_rom_observable_of_failure_flag_falseE
  (x : ms_public_input) :
  ms_rom_semantic_after_rom_observable_of_failure_flag x false =
  ms3a_pack_observable
    (ms3a_public_stmt_digest x)
    (ms3a_public_result_bit x)
    (ms3a_public_bitness_globals x)
    (ms3a_public_comparison_global x)
    (ms_public_transcript_digest_canonical x).
proof.
rewrite /ms_rom_semantic_after_rom_observable_of_failure_flag.
rewrite /ms3a_pack_observable_with_digest /ms3a_pack_observable_with_digest_digest.
rewrite /ms_public_transcript_digest_canonical.
rewrite /ms3a_public_stmt_digest /ms3a_public_result_bit.
rewrite /ms3a_public_bitness_globals /ms3a_public_comparison_global.
by rewrite /ms_result_bit_digest.
qed.

lemma ms_after_rom_public_semantic_observable_of_state_cleanE
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ! ms_rom_semantic_failure_event st =>
  ms_after_rom_public_semantic_observable_of_state x st =
  ms_rom_semantic_after_rom_observable_of_failure_flag x false.
proof.
move=> Hclean.
rewrite /ms_after_rom_public_semantic_observable_of_state Hclean.
by rewrite /ms_rom_semantic_after_rom_observable_of_failure_flag.
qed.

lemma ms_rom_public_observable_divergence_condition_cleanE
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ! ms_rom_semantic_failure_event st =>
  ! ms_rom_public_observable_divergence_condition x st.
proof.
move=> Hclean.
rewrite /ms_rom_public_observable_divergence_condition.
by rewrite /ms_after_rom_public_semantic_digest_of_state Hclean.
qed.

lemma ms_after_rom_public_semantic_observable_of_state_no_divergenceE
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ! ms_rom_public_observable_divergence_condition x st =>
  ms_after_rom_public_semantic_observable_of_state x st =
  ms_rom_semantic_after_rom_observable_of_failure_flag x false.
proof.
move=> Hnodiv.
have Hdigest :
    ms_after_rom_public_semantic_digest_of_state x st =
    ms_public_transcript_digest_canonical x.
  rewrite /ms_rom_public_observable_divergence_condition in Hnodiv.
  by smt().
have [Hfail|Hclean] : ms_rom_semantic_failure_event st \/
  ! ms_rom_semantic_failure_event st by smt().
- have HfailE : ms_rom_semantic_failure_event st = true by smt().
  rewrite /ms_after_rom_public_semantic_observable_of_state HfailE.
  rewrite (ms_rom_semantic_after_rom_observable_of_failure_flag_falseE x).
  by rewrite Hdigest.
exact (ms_after_rom_public_semantic_observable_of_state_cleanE x st Hclean).
qed.

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

lemma L_ms3c_real_execution_seed_on_support_public_challenge_fields
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  sigma.`ms3cep_challenge.`ms3csc_programmed_challenge =
    x.`mspi_comparison_global /\
  sigma.`ms3cep_challenge.`ms3csc_query_digest =
    ms3c_phase1_seed_query_digest x.
proof.
move=> Hsigma.
have [sr [Hsr ->]] := L_ms3c_real_execution_seed_support_inv x sigma Hsigma.
move: Hsr.
case: sr=> sc sa /= Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
move: Hsr=> [Hsc _].
have Hsurf := L_ms3c_real_seed_challenge_on_support_public_surface x sc Hsc.
by smt().
qed.

lemma ms_rom_public_observable_divergence_condition_query_collision_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticQueryCollision) =
  (sigma.`ms3cep_challenge.`ms3csc_programmed_challenge <>
   ms_public_transcript_digest_canonical x).
proof.
rewrite /ms_rom_public_observable_divergence_condition.
rewrite /ms_after_rom_public_semantic_digest_of_state.
rewrite (ms_rom_semantic_failure_event_stateE x sigma
  BudgetParameters.MSROMSemanticQueryCollision).
rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_query_collision_witness_of_category.
rewrite /ms_rom_expected_programmed_pair.
by rewrite /pred1 /=.
qed.

lemma ms_rom_public_divergence_query_collision_iff
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticQueryCollision) =
  ms_rom_public_divergence_global_digest_flag x.
proof.
move=> Hsigma.
rewrite ms_rom_public_observable_divergence_condition_query_collision_categoryE.
rewrite /ms_rom_public_divergence_global_digest_flag.
have [Hprog _] :=
  L_ms3c_real_execution_seed_on_support_public_challenge_fields x sigma Hsigma.
by rewrite Hprog.
qed.

lemma ms_rom_public_observable_divergence_condition_programming_collision_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticProgrammingCollision) =
  (sigma.`ms3cep_challenge.`ms3csc_programmed_challenge <>
   ms_public_transcript_digest_canonical x).
proof.
rewrite /ms_rom_public_observable_divergence_condition.
rewrite /ms_after_rom_public_semantic_digest_of_state.
rewrite (ms_rom_semantic_failure_event_stateE x sigma
  BudgetParameters.MSROMSemanticProgrammingCollision).
rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_programming_collision_witness_of_category.
by rewrite /pred1 /=.
qed.

lemma ms_rom_public_divergence_programming_collision_iff
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticProgrammingCollision) =
  ms_rom_public_divergence_global_digest_flag x.
proof.
move=> Hsigma.
rewrite ms_rom_public_observable_divergence_condition_programming_collision_categoryE.
rewrite /ms_rom_public_divergence_global_digest_flag.
have [Hprog _] :=
  L_ms3c_real_execution_seed_on_support_public_challenge_fields x sigma Hsigma.
by rewrite Hprog.
qed.

lemma ms_rom_public_divergence_collision_categories_share_global_digest_flag
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticQueryCollision) =
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticProgrammingCollision).
proof.
move=> Hsigma.
rewrite (ms_rom_public_divergence_query_collision_iff x sigma Hsigma).
rewrite (ms_rom_public_divergence_programming_collision_iff x sigma Hsigma).
by [].
qed.

lemma ms_rom_public_observable_divergence_condition_transcript_mismatch_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticTranscriptMismatch) =
  (sigma.`ms3cep_challenge.`ms3csc_query_digest <>
   ms_public_transcript_digest_canonical x).
proof.
rewrite /ms_rom_public_observable_divergence_condition.
rewrite /ms_after_rom_public_semantic_digest_of_state.
rewrite (ms_rom_semantic_failure_event_stateE x sigma
  BudgetParameters.MSROMSemanticTranscriptMismatch).
rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
rewrite /ms_rom_semantic_state_of_category_execution_seed /=.
rewrite /ms_rom_transcript_reconstruction_of_category_execution_seed.
by rewrite /pred1 /=.
qed.

lemma ms_rom_public_divergence_transcript_mismatch_iff
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticTranscriptMismatch) =
  ms_rom_public_divergence_query_digest_flag x.
proof.
move=> Hsigma.
rewrite ms_rom_public_observable_divergence_condition_transcript_mismatch_categoryE.
rewrite /ms_rom_public_divergence_query_digest_flag.
have [_ Hquery] :=
  L_ms3c_real_execution_seed_on_support_public_challenge_fields x sigma Hsigma.
by rewrite Hquery.
qed.

lemma ms_rom_public_observable_divergence_condition_of_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma category) =
  ms_rom_public_divergence_flag_of_category x category.
proof.
move=> Hsigma.
case: category Hsigma=> /= Hsigma.
- have Hclean :
      ! ms_rom_semantic_failure_event
        (ms_rom_semantic_state_of_category_execution_seed x sigma
          BudgetParameters.MSROMSemanticClean).
    rewrite (ms_rom_semantic_failure_event_stateE x sigma
      BudgetParameters.MSROMSemanticClean).
    by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
  have Hnodiv :=
    ms_rom_public_observable_divergence_condition_cleanE x
      (ms_rom_semantic_state_of_category_execution_seed x sigma
        BudgetParameters.MSROMSemanticClean) Hclean.
  by case: (ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticClean)) Hnodiv.
- exact (ms_rom_public_divergence_query_collision_iff x sigma Hsigma).
- exact (ms_rom_public_divergence_programming_collision_iff x sigma Hsigma).
exact (ms_rom_public_divergence_transcript_mismatch_iff x sigma Hsigma).
qed.

lemma ms_after_rom_public_semantic_observable_of_state_silent_failure_categoryE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed)
  (category : BudgetParameters.ms_rom_semantic_category) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_silent_failure_category x category =>
  ms_after_rom_public_semantic_observable_of_state x
    (ms_rom_semantic_state_of_category_execution_seed x sigma category) =
  ms_rom_semantic_after_rom_observable_of_failure_flag x false.
proof.
move=> Hsigma Hsilent.
have [_ Hflag] :
    BudgetParameters.ms_rom_semantic_category_is_failure category /\
    ! ms_rom_public_divergence_flag_of_category x category.
  by exact Hsilent.
have Hnodiv :
    ! ms_rom_public_observable_divergence_condition x
      (ms_rom_semantic_state_of_category_execution_seed x sigma category).
  rewrite (ms_rom_public_observable_divergence_condition_of_categoryE x sigma category Hsigma).
  exact Hflag.
exact (ms_after_rom_public_semantic_observable_of_state_no_divergenceE x
  (ms_rom_semantic_state_of_category_execution_seed x sigma category) Hnodiv).
qed.

lemma ms_rom_public_divergence_failure_categories_decompose_flags
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticQueryCollision) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticProgrammingCollision) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticTranscriptMismatch) =
    ms_rom_public_divergence_query_digest_flag x.
proof.
move=> Hsigma.
split.
- exact (ms_rom_public_divergence_query_collision_iff x sigma Hsigma).
split.
- exact (ms_rom_public_divergence_programming_collision_iff x sigma Hsigma).
exact (ms_rom_public_divergence_transcript_mismatch_iff x sigma Hsigma).
qed.

lemma ms_rom_public_divergence_failure_slots_decompose
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 0)) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 1)) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 2)) =
    ms_rom_public_divergence_query_digest_flag x.
proof.
move=> Hsigma.
have [Hquery [Hprog Hmismatch]] :=
  ms_rom_public_divergence_failure_categories_decompose_flags x sigma Hsigma.
rewrite /ms_rom_semantic_category_of_slot.
rewrite /BudgetParameters.ms_rom_query_collision_slot_count.
rewrite /BudgetParameters.ms_rom_programming_collision_slot_count.
rewrite /BudgetParameters.ms_rom_failure_slot_count /=.
by split; [exact Hquery | split; [exact Hprog | exact Hmismatch]].
qed.

lemma ms_rom_public_divergence_slot_image_on_supportE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) (slot : int) :
  sigma \in d_ms3c_real_execution_seed x =>
  slot \in ms_rom_semantic_slot_support =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot slot)) =
  if slot < BudgetParameters.ms_rom_query_collision_slot_count then
    ms_rom_public_divergence_global_digest_flag x
  else if slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count then
    ms_rom_public_divergence_global_digest_flag x
  else if slot < BudgetParameters.ms_rom_failure_slot_count then
    ms_rom_public_divergence_query_digest_flag x
  else false.
proof.
move=> Hsigma Hslot.
have [Hquery [Hprog Hmismatch]] :=
  ms_rom_public_divergence_failure_categories_decompose_flags x sigma Hsigma.
have [Hquery_slot|Hquery_slot] :
    slot < BudgetParameters.ms_rom_query_collision_slot_count \/
    !(slot < BudgetParameters.ms_rom_query_collision_slot_count) by smt().
- have Hquery_slotE :
      (slot < BudgetParameters.ms_rom_query_collision_slot_count) = true by smt().
  by rewrite /ms_rom_semantic_category_of_slot Hquery_slotE /= Hquery.
have Hquery_slotE :
    (slot < BudgetParameters.ms_rom_query_collision_slot_count) = false by smt().
have [Hprog_slot|Hprog_slot] :
    slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count \/
    !(slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count) by smt().
- have Hprog_slotE :
      (slot <
        BudgetParameters.ms_rom_query_collision_slot_count +
        BudgetParameters.ms_rom_programming_collision_slot_count) = true by smt().
  by rewrite /ms_rom_semantic_category_of_slot Hquery_slotE Hprog_slotE /= Hprog.
have Hprog_slotE :
    (slot <
      BudgetParameters.ms_rom_query_collision_slot_count +
      BudgetParameters.ms_rom_programming_collision_slot_count) = false by smt().
have [Hmismatch_slot|Hmismatch_slot] :
    slot < BudgetParameters.ms_rom_failure_slot_count \/
    !(slot < BudgetParameters.ms_rom_failure_slot_count) by smt().
- have Hmismatch_slotE :
      (slot < BudgetParameters.ms_rom_failure_slot_count) = true by smt().
  by rewrite /ms_rom_semantic_category_of_slot
    Hquery_slotE Hprog_slotE Hmismatch_slotE /= Hmismatch.
have Hmismatch_slotE :
    (slot < BudgetParameters.ms_rom_failure_slot_count) = false by smt().
have Hclean :
    ! ms_rom_semantic_failure_event
      (ms_rom_semantic_state_of_category_execution_seed x sigma
        BudgetParameters.MSROMSemanticClean).
  rewrite (ms_rom_semantic_failure_event_stateE x sigma
    BudgetParameters.MSROMSemanticClean).
  by rewrite /BudgetParameters.ms_rom_semantic_category_is_failure /pred1 /=.
have Hnodiv :=
  ms_rom_public_observable_divergence_condition_cleanE x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      BudgetParameters.MSROMSemanticClean) Hclean.
rewrite /ms_rom_semantic_category_of_slot Hquery_slotE Hprog_slotE Hmismatch_slotE /=.
by case: (ms_rom_public_observable_divergence_condition x
  (ms_rom_semantic_state_of_category_execution_seed x sigma
    BudgetParameters.MSROMSemanticClean)) Hnodiv.
qed.

lemma ms_rom_public_divergence_slot_choice_imageE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  dmap d_ms_rom_semantic_slot_choice
    (fun (slot : int) =>
      ms_rom_public_observable_divergence_condition x
        (ms_rom_semantic_state_of_category_execution_seed x sigma
          (ms_rom_semantic_category_of_slot slot))) =
  dmap d_ms_rom_semantic_slot_choice
    (fun (slot : int) =>
      if slot < BudgetParameters.ms_rom_query_collision_slot_count then
        ms_rom_public_divergence_global_digest_flag x
      else if slot <
          BudgetParameters.ms_rom_query_collision_slot_count +
          BudgetParameters.ms_rom_programming_collision_slot_count then
        ms_rom_public_divergence_global_digest_flag x
      else if slot < BudgetParameters.ms_rom_failure_slot_count then
        ms_rom_public_divergence_query_digest_flag x
      else false).
proof.
move=> Hsigma.
apply eq_dmap_in=> slot Hslot /=.
rewrite /d_ms_rom_semantic_slot_choice in Hslot.
rewrite supp_duniform in Hslot.
exact (ms_rom_public_divergence_slot_image_on_supportE x sigma slot Hsigma Hslot).
qed.

lemma ms_rom_public_divergence_demo_failure_slotsE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 0)) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 1)) =
    ms_rom_public_divergence_global_digest_flag x /\
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 2)) =
    ms_rom_public_divergence_query_digest_flag x.
proof.
move=> Hsigma.
have Hslot0 : 0 \in ms_rom_semantic_slot_support.
  by rewrite ms_rom_semantic_slot_supportE /=.
have Hslot1 : 1 \in ms_rom_semantic_slot_support.
  by rewrite ms_rom_semantic_slot_supportE /=.
have Hslot2 : 2 \in ms_rom_semantic_slot_support.
  by rewrite ms_rom_semantic_slot_supportE /=.
have H0 := ms_rom_public_divergence_slot_image_on_supportE x sigma 0 Hsigma Hslot0.
have H1 := ms_rom_public_divergence_slot_image_on_supportE x sigma 1 Hsigma Hslot1.
have H2 := ms_rom_public_divergence_slot_image_on_supportE x sigma 2 Hsigma Hslot2.
rewrite /BudgetParameters.ms_rom_query_collision_slot_count /= in H0.
rewrite /BudgetParameters.ms_rom_query_collision_slot_count
  /BudgetParameters.ms_rom_programming_collision_slot_count /= in H1.
rewrite /BudgetParameters.ms_rom_query_collision_slot_count
  /BudgetParameters.ms_rom_programming_collision_slot_count
  /BudgetParameters.ms_rom_transcript_mismatch_slot_count
  /BudgetParameters.ms_rom_failure_slot_count /= in H2.
by split; [exact H0 | split; [exact H1 | exact H2]].
qed.

lemma ms_rom_public_divergence_demo_clean_slot3E
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  ms_rom_public_observable_divergence_condition x
    (ms_rom_semantic_state_of_category_execution_seed x sigma
      (ms_rom_semantic_category_of_slot 3)) = false.
proof.
move=> Hsigma.
have Hslot3 : 3 \in ms_rom_semantic_slot_support.
  by rewrite ms_rom_semantic_slot_supportE /=.
have H3 := ms_rom_public_divergence_slot_image_on_supportE x sigma 3 Hsigma Hslot3.
rewrite /BudgetParameters.ms_rom_query_collision_slot_count
  /BudgetParameters.ms_rom_programming_collision_slot_count
  /BudgetParameters.ms_rom_transcript_mismatch_slot_count
  /BudgetParameters.ms_rom_failure_slot_count /= in H3.
exact H3.
qed.

lemma ms_rom_public_divergence_demo_slot0_3_imageE
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  map (fun (slot : int) =>
    ms_rom_public_observable_divergence_condition x
      (ms_rom_semantic_state_of_category_execution_seed x sigma
        (ms_rom_semantic_category_of_slot slot))) [0; 1; 2; 3] =
  [ ms_rom_public_divergence_global_digest_flag x;
    ms_rom_public_divergence_global_digest_flag x;
    ms_rom_public_divergence_query_digest_flag x;
    false ].
proof.
move=> Hsigma.
have [Hslot0 [Hslot1 Hslot2]] :=
  ms_rom_public_divergence_demo_failure_slotsE x sigma Hsigma.
have Hslot3 := ms_rom_public_divergence_demo_clean_slot3E x sigma Hsigma.
by rewrite /= Hslot0 Hslot1 Hslot2 Hslot3.
qed.

lemma ms_rom_public_observable_divergence_condition_implies_semantic_failure
  (x : ms_public_input) (st : ms_rom_semantic_state) :
  ms_rom_public_observable_divergence_condition x st =>
  ms_rom_semantic_failure_event st.
proof.
move=> Hdiv.
have [Hfail|Hclean] : ms_rom_semantic_failure_event st \/
  ! ms_rom_semantic_failure_event st by smt().
- exact Hfail.
have Hnodiv : ! ms_rom_public_observable_divergence_condition x st.
  exact (ms_rom_public_observable_divergence_condition_cleanE x st Hclean).
by smt().
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

op ms_rom_public_observable_divergence_mass
  (x : ms_public_input) : real =
  mu (d_ms_rom_semantic_coupled_state x)
    (ms_rom_public_observable_divergence_condition x).

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

lemma ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure
  (x : ms_public_input) :
  ms_rom_public_observable_divergence_mass x <=
  ms_rom_execution_owned_semantic_failure_probability x.
proof.
rewrite /ms_rom_public_observable_divergence_mass.
have Hsub :
    mu (d_ms_rom_semantic_coupled_state x)
      (ms_rom_public_observable_divergence_condition x) <=
    mu (d_ms_rom_semantic_coupled_state x)
      (fun st : ms_rom_semantic_state =>
        ms_rom_semantic_failure_event st).
  apply mu_sub => st /=.
  by smt(ms_rom_public_observable_divergence_condition_implies_semantic_failure).
have Hmass :
    mu (d_ms_rom_semantic_coupled_state x)
      (fun st : ms_rom_semantic_state =>
        ms_rom_semantic_failure_event st) =
    ms_rom_execution_owned_semantic_failure_probability x.
  have Hmu1 :
      mu (d_ms_rom_semantic_failure_state_choice x)
        (fun bad : bool => bad) =
      mu1 (d_ms_rom_semantic_failure_state_choice x) true.
    apply/mu_eq=> bad /=.
    by case: bad.
  rewrite /ms_rom_execution_owned_semantic_failure_probability.
  rewrite /d_ms_rom_semantic_failure_state_choice dmapE /= in Hmu1.
  exact Hmu1.
rewrite -Hmass.
exact Hsub.
qed.

lemma A_MS2_rom_programming_execution_owned_semantic_bound
  (x : ms_public_input) :
  ms_rom_execution_owned_semantic_failure_probability x <=
  BudgetParameters.epsilon_ms_rom_programmability_semantic.
proof.
rewrite ms_rom_execution_owned_semantic_failure_probability_eq_local_mass.
exact ms_rom_local_failure_mass_le_epsilon_ms_rom_programmability_semantic.
qed.