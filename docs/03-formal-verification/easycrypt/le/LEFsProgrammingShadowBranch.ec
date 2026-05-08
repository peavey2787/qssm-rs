require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LESurface.
require LEFsProgrammingCoreDefs.
require BudgetParameters.

(*---*) import RealOrder.

type le_fs_query_row = LEFsProgrammingCoreDefs.le_fs_query_row.

type le_fs_programmed_response_carrier =
  LEFsProgrammingCoreDefs.le_fs_programmed_response_carrier.

type le_fs_shadow_hidden_material = {
  lefshm_query_row : le_fs_query_row;
  lefshm_pre_query_material : le_query_material;
  lefshm_semantic_post_query_material : le_query_material;
  lefshm_programmed_response : le_fs_programmed_response_carrier;
  lefshm_bad_flag : bool;
}.

type le_fs_shadow_state = {
  lefss_pre_observable : le_transcript_observable;
  lefss_post_observable : le_transcript_observable;
  lefss_semantic_post_observable : le_transcript_observable;
  lefss_hidden_material : le_fs_shadow_hidden_material;
}.

op le_fs_shadow_branch_support : bool list =
  BudgetParameters.le_fs_semantic_branch_support.

op d_le_fs_shadow_branch_choice : bool distr =
  BudgetParameters.d_le_fs_semantic_branch_choice.

op d_le_fs_shadow_category_choice :
  BudgetParameters.le_fs_semantic_branch_category distr =
  BudgetParameters.d_le_fs_semantic_branch_category_choice.

op le_fs_shadow_local_bad_branch_mass : real =
  mu d_le_fs_shadow_branch_choice (fun (bad : bool) => bad).

op le_fs_shadow_programming_log_of_observable
  (obs : le_transcript_observable) : digest list =
  [le_challenge_seed_obs obs; le_programmed_query_digest_obs obs].

op le_fs_shadow_pre_query_material_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_query_material =
  {| leqm_row_challenge_seed =
       (le_fs_query_material_obs obs).`leqm_row_challenge_seed;
     leqm_row_programmed_query_digest =
       (le_fs_query_material_obs obs).`leqm_row_programmed_query_digest;
     leqm_programmed_response_digest =
       (le_fs_query_material_obs obs).`leqm_programmed_response_digest;
     leqm_programming_log =
       (le_fs_query_material_obs obs).`leqm_programming_log;
     leqm_bad_flag = bad |}.

op le_fs_shadow_semantic_post_query_material_of_observable
  (obs : le_transcript_observable) : le_query_material =
  {| leqm_row_challenge_seed = le_challenge_seed_obs obs;
     leqm_row_programmed_query_digest = le_programmed_query_digest_obs obs;
     leqm_programmed_response_digest = le_programmed_query_digest_obs obs;
     leqm_programming_log = le_fs_shadow_programming_log_of_observable obs;
     leqm_bad_flag = false |}.

op le_fs_shadow_hidden_material_of_observable_branch
  (obs : le_transcript_observable) (bad : bool) : le_fs_shadow_hidden_material =
  {| lefshm_query_row = LEFsProgrammingCoreDefs.le_fs_query_row_of_observable obs;
     lefshm_pre_query_material =
       le_fs_shadow_pre_query_material_of_observable obs bad;
     lefshm_semantic_post_query_material =
       le_fs_shadow_semantic_post_query_material_of_observable obs;
     lefshm_programmed_response =
       LEFsProgrammingCoreDefs.le_fs_programmed_response_of_observable obs;
     lefshm_bad_flag = bad |}.

op le_fs_shadow_hidden_material_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_hidden_material =
  le_fs_shadow_hidden_material_of_observable_branch obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

op le_fs_shadow_semantic_post_observable
  (hm : le_fs_shadow_hidden_material) : le_transcript_observable =
  {| leto_commitment_coeffs =
       le_commitment_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_t_coeffs =
       le_t_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_z_coeffs =
       le_z_coeffs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_challenge_seed_obs =
       le_challenge_seed_obs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_programmed_query_digest_obs =
       le_programmed_query_digest_obs
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
     leto_query_material = hm.`lefshm_semantic_post_query_material;
     leto_qssm_event_payload =
       le_qssm_event_payload
         (LEFsProgrammingCoreDefs.lefspc_programmed_view
            hm.`lefshm_programmed_response);
  |}.

op le_fs_shadow_semantic_programmed_view_of_observable
  (obs : le_transcript_observable) : le_transcript_observable =
  le_fs_shadow_semantic_post_observable
    (le_fs_shadow_hidden_material_of_observable_branch obs true).

op le_fs_shadow_semantic_branch_image_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_transcript_observable =
  if bad
  then le_fs_shadow_semantic_programmed_view_of_observable obs
  else LEFsProgrammingCoreDefs.le_fs_surrogate_transform obs.

op le_fs_shadow_post_of_observable
  (obs : le_transcript_observable) (hm : le_fs_shadow_hidden_material) :
  le_transcript_observable =
  if hm.`lefshm_bad_flag
  then le_fs_shadow_semantic_post_observable hm
  else LEFsProgrammingCoreDefs.le_fs_surrogate_transform obs.

op le_fs_shadow_projected_post_of_hidden_material
  (hm : le_fs_shadow_hidden_material) : le_transcript_observable =
  LEFsProgrammingCoreDefs.lefspc_programmed_view hm.`lefshm_programmed_response.

op le_fs_shadow_projected_post_of_observable
  (obs : le_transcript_observable) (bad : bool) : le_transcript_observable =
  le_fs_shadow_projected_post_of_hidden_material
    (le_fs_shadow_hidden_material_of_observable_branch obs bad).

op le_fs_shadow_state_of_branch_observable
  (obs : le_transcript_observable) (bad : bool) : le_fs_shadow_state =
  let hm = le_fs_shadow_hidden_material_of_observable_branch obs bad in
  {| lefss_pre_observable = obs;
     lefss_post_observable = le_fs_shadow_projected_post_of_hidden_material hm;
     lefss_semantic_post_observable = le_fs_shadow_post_of_observable obs hm;
     lefss_hidden_material = hm |}.

op le_fs_shadow_state_of_observable
  (obs : le_transcript_observable) : le_fs_shadow_state =
  le_fs_shadow_state_of_branch_observable obs
    ((le_fs_query_material_obs obs).`leqm_bad_flag).

op le_fs_shadow_state_of_category_observable
  (obs : le_transcript_observable)
  (category : BudgetParameters.le_fs_semantic_branch_category) : le_fs_shadow_state =
  le_fs_shadow_state_of_branch_observable obs
    (BudgetParameters.le_fs_semantic_branch_category_is_failure category).

op le_fs_shadow_pre_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_pre_observable.

op le_fs_shadow_post_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_post_observable.

op le_fs_shadow_semantic_post_state_observable
  (st : le_fs_shadow_state) : le_transcript_observable =
  st.`lefss_semantic_post_observable.

op le_fs_shadow_bad_event
  (st : le_fs_shadow_state) : bool =
  (le_fs_query_material_obs st.`lefss_pre_observable).`leqm_bad_flag /\
  ! (le_fs_query_material_obs st.`lefss_post_observable).`leqm_bad_flag.

op le_fs_shadow_semantic_bad_event
  (st : le_fs_shadow_state) : bool =
  st.`lefss_hidden_material.`lefshm_pre_query_material.`leqm_bad_flag /\
  ! (le_fs_query_material_obs st.`lefss_semantic_post_observable).`leqm_bad_flag.

op le_fs_shadow_branch_condition
  (st : le_fs_shadow_state) : bool =
  st.`lefss_hidden_material.`lefshm_bad_flag =
  le_fs_shadow_semantic_bad_event st.

op le_fs_shadow_clean_condition
  (st : le_fs_shadow_state) : bool =
  ! le_fs_shadow_semantic_bad_event st /\
  st.`lefss_semantic_post_observable =
    LEFsProgrammingCoreDefs.le_fs_surrogate_transform st.`lefss_pre_observable.

op le_fs_shadow_query_collision_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  LEFsProgrammingCoreDefs.lefsqr_challenge_seed
      st.`lefss_hidden_material.`lefshm_query_row =
    st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_row_challenge_seed /\
  LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
      st.`lefss_hidden_material.`lefshm_query_row =
    st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_row_programmed_query_digest.

op le_fs_shadow_programming_collision_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_programmed_response_digest =
    LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
      st.`lefss_hidden_material.`lefshm_query_row /\
  st.`lefss_hidden_material.`lefshm_semantic_post_query_material.`leqm_programming_log =
    [ LEFsProgrammingCoreDefs.lefsqr_challenge_seed
        st.`lefss_hidden_material.`lefshm_query_row;
      LEFsProgrammingCoreDefs.lefsqr_programmed_query_digest
        st.`lefss_hidden_material.`lefshm_query_row ].

op le_fs_shadow_transcript_mismatch_condition
  (st : le_fs_shadow_state) : bool =
  le_fs_shadow_semantic_bad_event st /\
  le_challenge_seed_obs st.`lefss_semantic_post_observable =
    le_challenge_seed_obs st.`lefss_post_observable /\
  le_programmed_query_digest_obs st.`lefss_semantic_post_observable =
    le_programmed_query_digest_obs st.`lefss_post_observable /\
  ! (le_fs_query_material_obs st.`lefss_semantic_post_observable).`leqm_bad_flag.

op le_fs_shadow_semantic_category_condition
  (category : BudgetParameters.le_fs_semantic_branch_category)
  (st : le_fs_shadow_state) : bool =
  if pred1 BudgetParameters.LEFSSemanticBranchClean category then
    le_fs_shadow_clean_condition st
  else if pred1 BudgetParameters.LEFSSemanticBranchQueryCollision category then
    le_fs_shadow_query_collision_condition st
  else if pred1 BudgetParameters.LEFSSemanticBranchProgrammingCollision category then
    le_fs_shadow_programming_collision_condition st
  else le_fs_shadow_transcript_mismatch_condition st.

pred le_fs_shadow_good_event
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) =
  ! (le_fs_query_material_obs obs).`leqm_bad_flag.