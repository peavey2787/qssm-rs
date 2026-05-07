require import QssmTypes Domains FS SourceModel.
require import AllCore List Distr.
require BudgetParameters.

(* Lower LE real-execution observable surface. The output carrier is concrete,
  and the hidden query-material carrier is now the concrete unit surface. *)
type le_real_execution_challenge_seed_material = {
  lerecsm_branch : bool;
  lerecsm_digest_1 : digest;
  lerecsm_digest_2 : digest;
  lerecsm_digest_3 : digest;
  lerecsm_digest_4 : digest;
}.

type le_real_execution_programmed_query_digest_material = {
  lerepqm_digest_1 : digest;
  lerepqm_digest_2 : digest;
  lerepqm_digest_3 : digest;
  lerepqm_digest_4 : digest;
  lerepqm_digest_5 : digest;
}.

type le_real_execution_primitive_material = {
  lerem_commitment_coeffs : coeff_vector;
  lerem_t_coeffs : coeff_vector;
  lerem_z_coeffs : coeff_vector;
  lerem_challenge_seed_material : le_real_execution_challenge_seed_material;
  lerem_programmed_query_digest_material :
    le_real_execution_programmed_query_digest_material;
  lerem_query_material : le_query_material;
}.

type le_real_execution_residual_material = {
  lererm_commitment_coeffs : coeff_vector;
  lererm_t_coeffs : coeff_vector;
  lererm_z_coeffs : coeff_vector;
  lererm_query_material : le_query_material;
}.

type le_real_execution_public_spine = {
  lereps_commitment_coeffs : coeff_vector;
  lereps_t_coeffs : coeff_vector;
  lereps_z_coeffs : coeff_vector;
  lereps_challenge_seed_obs : digest;
  lereps_programmed_query_digest_obs : digest;
}.

type le_real_execution_spine = {
  leres_public_spine : le_real_execution_public_spine;
  leres_query_material : le_query_material;
}.

type le_real_execution_record = {
  lerec_commitment_coeffs : coeff_vector;
  lerec_t_coeffs : coeff_vector;
  lerec_z_coeffs : coeff_vector;
  lerec_challenge_seed_obs : digest;
  lerec_programmed_query_digest_obs : digest;
  lerec_query_material : le_query_material;
}.

type le_real_execution_semantic_rejection_decision = {
  leresd_reject : bool;
  leresd_repairs_hidden_query_material : bool;
}.

type le_real_execution_semantic_rejection_ticket = {
  lerest_decision : le_real_execution_semantic_rejection_decision;
  lerest_challenge_seed_material : le_real_execution_challenge_seed_material;
  lerest_programmed_query_digest_material :
    le_real_execution_programmed_query_digest_material;
  lerest_query_material : le_query_material;
}.

op le_real_execution_hidden_query_row_challenge_seed
  (s : seed) : digest =
  le_challenge_seed
    DOMAIN_LE_FS
    DOMAIN_LE_CHALLENGE_POLY
    false
    s
    (hash_domain DOMAIN_LE_FS [])
    (hash_domain DOMAIN_LE_CHALLENGE_POLY [])
    (hash_domain LABEL_LE_GLOBAL_SIM_CHALLENGE_SEED [])
    (hash_domain LABEL_CROSS_PROTOCOL_DIGEST_V1 []).

op le_real_execution_hidden_query_row_programmed_query_digest
  (s : seed) : digest =
  le_programmed_query_digest
    LABEL_LE_PROGRAMMED_QUERY_DIGEST
    (le_real_execution_hidden_query_row_challenge_seed s)
    (hash_domain LABEL_LE_PROGRAMMED_QUERY_DIGEST [])
    (hash_domain LABEL_FS_V2 [])
    (hash_domain LABEL_DST_LE_COMMIT [])
    (hash_domain DOMAIN_ZK_SIM []).

op le_real_execution_hidden_query_material_of
  (x : qssm_public_input) (s : seed) : le_query_material =
  {| leqm_row_challenge_seed =
       le_real_execution_hidden_query_row_challenge_seed s;
     leqm_row_programmed_query_digest =
       le_real_execution_hidden_query_row_programmed_query_digest s;
     leqm_programmed_response_digest = hash_domain LABEL_FS_V2 [];
     leqm_programming_log = [];
     leqm_bad_flag = false |}.

op le_real_execution_constant_coeff_vector (tag : int) : coeff_vector = [tag].

op le_real_execution_commitment_coeffs_of
  (x : qssm_public_input) (s : seed) : coeff_vector =
  le_real_execution_constant_coeff_vector 0.

op le_real_execution_t_coeffs_of
  (x : qssm_public_input) (s : seed) : coeff_vector =
  le_real_execution_constant_coeff_vector 1.

op le_real_execution_z_coeffs_of
  (x : qssm_public_input) (s : seed) : coeff_vector =
  le_real_execution_constant_coeff_vector 2.

op le_real_execution_residual_material_of
  (x : qssm_public_input) (s : seed) : le_real_execution_residual_material =
  {|
    lererm_commitment_coeffs = le_real_execution_commitment_coeffs_of x s;
    lererm_t_coeffs = le_real_execution_t_coeffs_of x s;
    lererm_z_coeffs = le_real_execution_z_coeffs_of x s;
    lererm_query_material = le_real_execution_hidden_query_material_of x s;
  |}.

op le_real_execution_label_digest (label : domain_label) : digest =
  hash_domain label [].

op le_real_execution_challenge_seed_material_of
  (x : qssm_public_input) (s : seed) : le_real_execution_challenge_seed_material =
  {|
    lerecsm_branch = false;
    lerecsm_digest_1 = le_real_execution_label_digest DOMAIN_LE_FS;
    lerecsm_digest_2 = le_real_execution_label_digest DOMAIN_LE_CHALLENGE_POLY;
    lerecsm_digest_3 = le_real_execution_label_digest LABEL_LE_GLOBAL_SIM_CHALLENGE_SEED;
    lerecsm_digest_4 = le_real_execution_label_digest LABEL_CROSS_PROTOCOL_DIGEST_V1;
  |}.

op le_real_execution_semantic_rejection_category_is_failure
  (category : BudgetParameters.le_rejection_semantic_ticket_category) : bool =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.

(* Execution only interprets the primitive category law into the existing
   reject/repair decision surface; category probabilities remain owned by
   BudgetParameters. *)
op le_real_execution_semantic_rejection_decision_of_category
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_real_execution_semantic_rejection_decision =
  let reject = le_real_execution_semantic_rejection_category_is_failure category in
  {|
    leresd_reject = reject;
    leresd_repairs_hidden_query_material = reject;
  |}.

op d_le_real_execution_semantic_rejection_category_choice :
  BudgetParameters.le_rejection_semantic_ticket_category distr =
  BudgetParameters.d_le_rejection_semantic_ticket_category_choice.

op d_le_real_execution_semantic_rejection_decision_choice :
  le_real_execution_semantic_rejection_decision distr =
  dmap d_le_real_execution_semantic_rejection_category_choice
    le_real_execution_semantic_rejection_decision_of_category.

op le_real_execution_semantic_rejection_decision_reject
  (decision : le_real_execution_semantic_rejection_decision) : bool =
  decision.`leresd_reject.

op le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
  (decision : le_real_execution_semantic_rejection_decision) : bool =
  decision.`leresd_repairs_hidden_query_material.

lemma le_real_execution_semantic_rejection_decision_of_category_rejectE
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_real_execution_semantic_rejection_decision_reject
    (le_real_execution_semantic_rejection_decision_of_category category) =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_reject
  /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure.
qed.

lemma le_real_execution_semantic_rejection_decision_of_category_repairs_hidden_query_materialE
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
    (le_real_execution_semantic_rejection_decision_of_category category) =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
  /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure.
qed.

lemma le_real_execution_semantic_rejection_soft_repair_decisionE :
  le_real_execution_semantic_rejection_decision_of_category
    BudgetParameters.LERejectionSemanticTicketSoftRepair =
  {| leresd_reject = true;
     leresd_repairs_hidden_query_material = true |}.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure
  /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
qed.

lemma le_real_execution_semantic_rejection_hard_repair_decisionE :
  le_real_execution_semantic_rejection_decision_of_category
    BudgetParameters.LERejectionSemanticTicketHardRepair =
  {| leresd_reject = true;
     leresd_repairs_hidden_query_material = true |}.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure
  /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
qed.

lemma le_real_execution_semantic_rejection_invalid_decisionE :
  le_real_execution_semantic_rejection_decision_of_category
    BudgetParameters.LERejectionSemanticTicketInvalid =
  {| leresd_reject = true;
     leresd_repairs_hidden_query_material = true |}.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure
  /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
qed.

lemma le_real_execution_semantic_rejection_accept_decisionE :
  le_real_execution_semantic_rejection_decision_of_category
    BudgetParameters.LERejectionSemanticTicketAccept =
  {| leresd_reject = false;
     leresd_repairs_hidden_query_material = false |}.
proof.
by rewrite /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure
  /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
qed.

op le_real_execution_semantic_rejection_branch_support : bool list =
  BudgetParameters.le_rejection_semantic_branch_support.

op d_le_real_execution_semantic_rejection_branch_choice : bool distr =
  dmap d_le_real_execution_semantic_rejection_decision_choice
    le_real_execution_semantic_rejection_decision_reject.

op d_le_real_execution_semantic_rejection_decision_repair_choice : bool distr =
  dmap d_le_real_execution_semantic_rejection_decision_choice
    le_real_execution_semantic_rejection_decision_repairs_hidden_query_material.

lemma d_le_real_execution_semantic_rejection_branch_choiceE :
  d_le_real_execution_semantic_rejection_branch_choice =
  BudgetParameters.d_le_rejection_semantic_branch_choice.
proof.
rewrite /d_le_real_execution_semantic_rejection_branch_choice.
rewrite /d_le_real_execution_semantic_rejection_decision_choice.
rewrite /d_le_real_execution_semantic_rejection_category_choice.
rewrite (dmap_comp le_real_execution_semantic_rejection_decision_of_category
  le_real_execution_semantic_rejection_decision_reject
  BudgetParameters.d_le_rejection_semantic_ticket_category_choice).
have Hmap :
  dmap BudgetParameters.d_le_rejection_semantic_ticket_category_choice
    (le_real_execution_semantic_rejection_decision_reject
      \o le_real_execution_semantic_rejection_decision_of_category) =
  dmap BudgetParameters.d_le_rejection_semantic_ticket_category_choice
    BudgetParameters.le_rejection_semantic_ticket_category_is_failure.
  apply eq_dmap_in=> category _ /=.
  by rewrite /le_real_execution_semantic_rejection_decision_reject
    /le_real_execution_semantic_rejection_decision_of_category
    /le_real_execution_semantic_rejection_category_is_failure /(\o).
rewrite Hmap.
by rewrite /BudgetParameters.d_le_rejection_semantic_branch_choice
  /BudgetParameters.d_le_rejection_semantic_ticket_repair_choice.
qed.

lemma d_le_real_execution_semantic_rejection_decision_repair_choiceE :
  d_le_real_execution_semantic_rejection_decision_repair_choice =
  BudgetParameters.d_le_rejection_semantic_ticket_repair_choice.
proof.
rewrite /d_le_real_execution_semantic_rejection_decision_repair_choice.
rewrite /d_le_real_execution_semantic_rejection_decision_choice.
rewrite /d_le_real_execution_semantic_rejection_category_choice.
rewrite (dmap_comp le_real_execution_semantic_rejection_decision_of_category
  le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
  BudgetParameters.d_le_rejection_semantic_ticket_category_choice).
have Hmap :
  dmap BudgetParameters.d_le_rejection_semantic_ticket_category_choice
    (le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
      \o le_real_execution_semantic_rejection_decision_of_category) =
  dmap BudgetParameters.d_le_rejection_semantic_ticket_category_choice
    BudgetParameters.le_rejection_semantic_ticket_category_is_failure.
  apply eq_dmap_in=> category _ /=.
  by rewrite /le_real_execution_semantic_rejection_decision_repairs_hidden_query_material
    /le_real_execution_semantic_rejection_decision_of_category /(\o)
    /le_real_execution_semantic_rejection_category_is_failure.
rewrite Hmap.
by rewrite /BudgetParameters.d_le_rejection_semantic_ticket_repair_choice.
qed.

lemma le_real_execution_semantic_rejection_decision_choice_support_repairs_hidden_query_materialE
  (decision : le_real_execution_semantic_rejection_decision) :
  decision \in d_le_real_execution_semantic_rejection_decision_choice =>
  decision.`leresd_repairs_hidden_query_material = decision.`leresd_reject.
proof.
move=> Hdecision.
rewrite /d_le_real_execution_semantic_rejection_decision_choice in Hdecision.
rewrite /d_le_real_execution_semantic_rejection_category_choice in Hdecision.
rewrite supp_dmap in Hdecision.
elim Hdecision=> category [Hcategory ->].
by rewrite /le_real_execution_semantic_rejection_decision_of_category.
qed.

lemma le_real_execution_semantic_rejection_branch_choice_lossless :
  is_lossless d_le_real_execution_semantic_rejection_branch_choice.
proof.
rewrite d_le_real_execution_semantic_rejection_branch_choiceE.
exact BudgetParameters.le_rejection_semantic_branch_choice_lossless.
qed.

lemma le_real_execution_semantic_rejection_accept_branch_has_support :
  false \in d_le_real_execution_semantic_rejection_branch_choice.
proof.
rewrite d_le_real_execution_semantic_rejection_branch_choiceE.
exact BudgetParameters.le_rejection_semantic_accept_branch_has_support.
qed.

lemma le_real_execution_semantic_rejection_reject_branch_has_support :
  true \in d_le_real_execution_semantic_rejection_branch_choice.
proof.
rewrite d_le_real_execution_semantic_rejection_branch_choiceE.
exact BudgetParameters.le_rejection_semantic_reject_branch_has_support.
qed.

lemma le_real_execution_semantic_rejection_branch_choice_mass_false :
  mu1 d_le_real_execution_semantic_rejection_branch_choice false =
  (BudgetParameters.le_rejection_semantic_total_slot_count -
   BudgetParameters.le_rejection_semantic_reject_slot_count)%r /
  BudgetParameters.le_rejection_semantic_total_slot_count%r.
proof.
rewrite d_le_real_execution_semantic_rejection_branch_choiceE.
exact BudgetParameters.le_rejection_semantic_branch_choice_mass_false.
qed.

lemma le_real_execution_semantic_rejection_branch_choice_mass_true :
  mu1 d_le_real_execution_semantic_rejection_branch_choice true =
  BudgetParameters.le_rejection_semantic_reject_slot_count%r /
  BudgetParameters.le_rejection_semantic_total_slot_count%r.
proof.
rewrite d_le_real_execution_semantic_rejection_branch_choiceE.
exact BudgetParameters.le_rejection_semantic_branch_choice_mass_true.
qed.

op le_real_execution_semantic_rejection_challenge_seed_material_of_branch
  (x : qssm_public_input) (s : seed) (reject : bool) :
  le_real_execution_challenge_seed_material =
  {|
    lerecsm_branch = reject;
    lerecsm_digest_1 =
      (le_real_execution_challenge_seed_material_of x s).`lerecsm_digest_1;
    lerecsm_digest_2 =
      (le_real_execution_challenge_seed_material_of x s).`lerecsm_digest_2;
    lerecsm_digest_3 =
      (le_real_execution_challenge_seed_material_of x s).`lerecsm_digest_3;
    lerecsm_digest_4 =
      (le_real_execution_challenge_seed_material_of x s).`lerecsm_digest_4;
  |}.

op le_real_execution_challenge_seed_obs_of_challenge_material
  (s : seed) (mat : le_real_execution_challenge_seed_material) : digest =
  le_challenge_seed
    DOMAIN_LE_FS
    DOMAIN_LE_CHALLENGE_POLY
    mat.`lerecsm_branch
    s
    mat.`lerecsm_digest_1
    mat.`lerecsm_digest_2
    mat.`lerecsm_digest_3
    mat.`lerecsm_digest_4.

op le_real_execution_semantic_rejection_challenge_seed_obs_of_branch
  (x : qssm_public_input) (s : seed) (reject : bool) : digest =
  le_real_execution_challenge_seed_obs_of_challenge_material s
    (le_real_execution_semantic_rejection_challenge_seed_material_of_branch x s reject).

op le_real_execution_programmed_query_digest_material_of
  (x : qssm_public_input) (s : seed) : le_real_execution_programmed_query_digest_material =
  {|
    lerepqm_digest_1 =
      le_real_execution_challenge_seed_obs_of_challenge_material s
        (le_real_execution_challenge_seed_material_of x s);
    lerepqm_digest_2 = le_real_execution_label_digest LABEL_LE_PROGRAMMED_QUERY_DIGEST;
    lerepqm_digest_3 = le_real_execution_label_digest LABEL_FS_V2;
    lerepqm_digest_4 = le_real_execution_label_digest LABEL_DST_LE_COMMIT;
    lerepqm_digest_5 = le_real_execution_label_digest DOMAIN_ZK_SIM;
  |}.

op le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch
  (x : qssm_public_input) (s : seed) (reject : bool) :
  le_real_execution_programmed_query_digest_material =
  {|
    lerepqm_digest_1 =
      le_real_execution_semantic_rejection_challenge_seed_obs_of_branch x s reject;
    lerepqm_digest_2 =
      (le_real_execution_programmed_query_digest_material_of x s).`lerepqm_digest_2;
    lerepqm_digest_3 =
      (le_real_execution_programmed_query_digest_material_of x s).`lerepqm_digest_3;
    lerepqm_digest_4 =
      (le_real_execution_programmed_query_digest_material_of x s).`lerepqm_digest_4;
    lerepqm_digest_5 =
      (le_real_execution_programmed_query_digest_material_of x s).`lerepqm_digest_5;
  |}.

op le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch
  (x : qssm_public_input) (s : seed) (reject : bool) : digest =
  le_programmed_query_digest
    LABEL_LE_PROGRAMMED_QUERY_DIGEST
    (le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject).`lerepqm_digest_1
    (le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject).`lerepqm_digest_2
    (le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject).`lerepqm_digest_3
    (le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject).`lerepqm_digest_4
    (le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject).`lerepqm_digest_5.

op le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_query_material =
  if reject then
    let repaired_challenge_seed =
      le_real_execution_semantic_rejection_challenge_seed_obs_of_branch x s reject in
    let repaired_programmed_query_digest =
      le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch x s reject in
    {|
      leqm_row_challenge_seed = repaired_challenge_seed;
      leqm_row_programmed_query_digest = repaired_programmed_query_digest;
      leqm_programmed_response_digest =
        obs.`leto_query_material.`leqm_programmed_response_digest;
      leqm_programming_log =
        obs.`leto_query_material.`leqm_programming_log ++
        [repaired_challenge_seed; repaired_programmed_query_digest];
      leqm_bad_flag = obs.`leto_query_material.`leqm_bad_flag;
    |}
  else obs.`leto_query_material.

op le_real_execution_semantic_rejection_ticket_of_observable_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_real_execution_semantic_rejection_ticket =
  let decision =
    {| leresd_reject = reject;
       leresd_repairs_hidden_query_material = reject |} in
  {|
    lerest_decision = decision;
    lerest_challenge_seed_material =
      le_real_execution_semantic_rejection_challenge_seed_material_of_branch x s reject;
    lerest_programmed_query_digest_material =
      le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch x s reject;
    lerest_query_material =
      le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch x s obs reject;
  |}.

op le_real_execution_semantic_rejection_primitive_material_of_observable_ticket
  (obs : le_transcript_observable)
  (ticket : le_real_execution_semantic_rejection_ticket) :
  le_real_execution_primitive_material =
  {|
    lerem_commitment_coeffs = obs.`leto_commitment_coeffs;
    lerem_t_coeffs = obs.`leto_t_coeffs;
    lerem_z_coeffs = obs.`leto_z_coeffs;
    lerem_challenge_seed_material = ticket.`lerest_challenge_seed_material;
    lerem_programmed_query_digest_material =
      ticket.`lerest_programmed_query_digest_material;
    lerem_query_material = ticket.`lerest_query_material;
  |}.

op le_real_execution_semantic_rejection_primitive_material_of_observable_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_real_execution_primitive_material =
  le_real_execution_semantic_rejection_primitive_material_of_observable_ticket obs
    (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs reject).

op le_real_execution_primitive_material_of
  (x : qssm_public_input) (s : seed) : le_real_execution_primitive_material =
  {|
    lerem_commitment_coeffs =
      (le_real_execution_residual_material_of x s).`lererm_commitment_coeffs;
    lerem_t_coeffs =
      (le_real_execution_residual_material_of x s).`lererm_t_coeffs;
    lerem_z_coeffs =
      (le_real_execution_residual_material_of x s).`lererm_z_coeffs;
    lerem_challenge_seed_material =
      le_real_execution_challenge_seed_material_of x s;
    lerem_programmed_query_digest_material =
      le_real_execution_programmed_query_digest_material_of x s;
    lerem_query_material =
      (le_real_execution_residual_material_of x s).`lererm_query_material;
  |}.

op le_real_execution_challenge_seed_obs_of_material
  (s : seed) (mat : le_real_execution_primitive_material) : digest =
  le_real_execution_challenge_seed_obs_of_challenge_material s
    mat.`lerem_challenge_seed_material.

op le_real_execution_programmed_query_digest_obs_of_material
  (mat : le_real_execution_primitive_material) : digest =
  le_programmed_query_digest
    LABEL_LE_PROGRAMMED_QUERY_DIGEST
    mat.`lerem_programmed_query_digest_material.`lerepqm_digest_1
    mat.`lerem_programmed_query_digest_material.`lerepqm_digest_2
    mat.`lerem_programmed_query_digest_material.`lerepqm_digest_3
    mat.`lerem_programmed_query_digest_material.`lerepqm_digest_4
    mat.`lerem_programmed_query_digest_material.`lerepqm_digest_5.

op le_real_execution_semantic_rejection_observable_of_observable_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_transcript_observable =
  let ticket =
    le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs reject in
  if ticket.`lerest_decision.`leresd_reject then
    let mat =
      le_real_execution_semantic_rejection_primitive_material_of_observable_ticket obs ticket in
    {|
      leto_commitment_coeffs = obs.`leto_commitment_coeffs;
      leto_t_coeffs = obs.`leto_t_coeffs;
      leto_z_coeffs = obs.`leto_z_coeffs;
      leto_challenge_seed_obs =
        le_real_execution_challenge_seed_obs_of_material s mat;
      leto_programmed_query_digest_obs =
        le_real_execution_programmed_query_digest_obs_of_material mat;
      leto_query_material = ticket.`lerest_query_material;
      leto_qssm_event_payload = obs.`leto_qssm_event_payload;
    |}
  else obs.

lemma le_real_execution_semantic_rejection_accept_branch_id
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  le_real_execution_semantic_rejection_observable_of_observable_branch x s obs false = obs.
proof.
by rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch
  /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
qed.

lemma le_real_execution_semantic_rejection_observable_preserves_commitment_coeffs
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) (reject : bool) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs reject).`leto_commitment_coeffs =
  obs.`leto_commitment_coeffs.
proof.
case: reject=> /=.
  by rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch
    /le_real_execution_semantic_rejection_ticket_of_observable_branch.
by rewrite le_real_execution_semantic_rejection_accept_branch_id.
qed.

lemma le_real_execution_semantic_rejection_observable_preserves_t_coeffs
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) (reject : bool) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs reject).`leto_t_coeffs =
  obs.`leto_t_coeffs.
proof.
case: reject=> /=.
  by rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch
    /le_real_execution_semantic_rejection_ticket_of_observable_branch.
by rewrite le_real_execution_semantic_rejection_accept_branch_id.
qed.

lemma le_real_execution_semantic_rejection_observable_preserves_z_coeffs
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) (reject : bool) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs reject).`leto_z_coeffs =
  obs.`leto_z_coeffs.
proof.
case: reject=> /=.
  by rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch
    /le_real_execution_semantic_rejection_ticket_of_observable_branch.
by rewrite le_real_execution_semantic_rejection_accept_branch_id.
qed.

lemma le_real_execution_semantic_rejection_observable_preserves_qssm_event_payload
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) (reject : bool) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs reject).`leto_qssm_event_payload =
  obs.`leto_qssm_event_payload.
proof.
case: reject=> /=.
  by rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch
    /le_real_execution_semantic_rejection_ticket_of_observable_branch.
by rewrite le_real_execution_semantic_rejection_accept_branch_id.
qed.

lemma le_real_execution_semantic_rejection_reject_query_material_matches_challenge_seed_obs
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs true).`leto_query_material.`leqm_row_challenge_seed =
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs true).`leto_challenge_seed_obs.
proof.
rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /le_real_execution_semantic_rejection_primitive_material_of_observable_ticket.
rewrite /le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch /=.
rewrite /le_real_execution_challenge_seed_obs_of_material.
rewrite /le_real_execution_semantic_rejection_challenge_seed_obs_of_branch.
rewrite /le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch /=.
by [].
qed.

lemma le_real_execution_semantic_rejection_reject_query_material_matches_programmed_query_digest_obs
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs true).`leto_query_material.`leqm_row_programmed_query_digest =
  (le_real_execution_semantic_rejection_observable_of_observable_branch x s obs true).`leto_programmed_query_digest_obs.
proof.
rewrite /le_real_execution_semantic_rejection_observable_of_observable_branch.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /le_real_execution_semantic_rejection_primitive_material_of_observable_ticket.
rewrite /le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch /=.
rewrite /le_real_execution_semantic_rejection_challenge_seed_obs_of_branch.
rewrite /le_real_execution_programmed_query_digest_obs_of_material.
rewrite /le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch /=.
by [].
qed.

op le_real_execution_spine_of
  (x : qssm_public_input) (s : seed) : le_real_execution_spine =
  {|
    leres_public_spine = {|
      lereps_commitment_coeffs =
        (le_real_execution_primitive_material_of x s).`lerem_commitment_coeffs;
      lereps_t_coeffs =
        (le_real_execution_primitive_material_of x s).`lerem_t_coeffs;
      lereps_z_coeffs =
        (le_real_execution_primitive_material_of x s).`lerem_z_coeffs;
      lereps_challenge_seed_obs =
        le_real_execution_challenge_seed_obs_of_material s
          (le_real_execution_primitive_material_of x s);
      lereps_programmed_query_digest_obs =
        le_real_execution_programmed_query_digest_obs_of_material
          (le_real_execution_primitive_material_of x s);
    |};
    leres_query_material =
      (le_real_execution_primitive_material_of x s).`lerem_query_material;
  |}.

op le_real_execution_public_spine_of_spine
  (st : le_real_execution_spine) : le_real_execution_public_spine =
  st.`leres_public_spine.

op le_real_execution_query_material_of_spine
  (st : le_real_execution_spine) : le_query_material =
  st.`leres_query_material.

op le_real_execution_record_of
  (x : qssm_public_input) (s : seed) : le_real_execution_record =
  {|
    lerec_commitment_coeffs =
      (le_real_execution_public_spine_of_spine
        (le_real_execution_spine_of x s)).`lereps_commitment_coeffs;
    lerec_t_coeffs =
      (le_real_execution_public_spine_of_spine
        (le_real_execution_spine_of x s)).`lereps_t_coeffs;
    lerec_z_coeffs =
      (le_real_execution_public_spine_of_spine
        (le_real_execution_spine_of x s)).`lereps_z_coeffs;
    lerec_challenge_seed_obs =
      (le_real_execution_public_spine_of_spine
        (le_real_execution_spine_of x s)).`lereps_challenge_seed_obs;
    lerec_programmed_query_digest_obs =
      (le_real_execution_public_spine_of_spine
        (le_real_execution_spine_of x s)).`lereps_programmed_query_digest_obs;
    lerec_query_material =
      le_real_execution_query_material_of_spine (le_real_execution_spine_of x s);
  |}.

op le_real_execution_commitment_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector =
  (le_real_execution_record_of x s).`lerec_commitment_coeffs.

op le_real_execution_t_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector =
  (le_real_execution_record_of x s).`lerec_t_coeffs.

op le_real_execution_z_coeffs
  (x : qssm_public_input) (s : seed) : coeff_vector =
  (le_real_execution_record_of x s).`lerec_z_coeffs.

op le_real_execution_challenge_seed_obs
  (x : qssm_public_input) (s : seed) : digest =
  (le_real_execution_record_of x s).`lerec_challenge_seed_obs.

op le_real_execution_programmed_query_digest_obs
  (x : qssm_public_input) (s : seed) : digest =
  (le_real_execution_record_of x s).`lerec_programmed_query_digest_obs.

op le_real_execution_query_material
  (x : qssm_public_input) (s : seed) : le_query_material =
  (le_real_execution_record_of x s).`lerec_query_material.

op le_real_execution_qssm_event_payload
  (x : qssm_public_input) (s : seed) : qssm_event_payload =
  qssm_event_payload_of_ms_public (extract_ms_public x).

op le_real_execution_observable
  (x : qssm_public_input) (s : seed) : le_transcript_observable =
  {|
    leto_commitment_coeffs = (le_real_execution_record_of x s).`lerec_commitment_coeffs;
    leto_t_coeffs = (le_real_execution_record_of x s).`lerec_t_coeffs;
    leto_z_coeffs = (le_real_execution_record_of x s).`lerec_z_coeffs;
    leto_challenge_seed_obs = (le_real_execution_record_of x s).`lerec_challenge_seed_obs;
    leto_programmed_query_digest_obs =
      (le_real_execution_record_of x s).`lerec_programmed_query_digest_obs;
    leto_query_material = (le_real_execution_record_of x s).`lerec_query_material;
    leto_qssm_event_payload = le_real_execution_qssm_event_payload x s;
  |}.

op d_le_real_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dunit (le_real_execution_observable x s).

op d_le_real_execution_semantic_rejection_ticket_choice
  (x : qssm_public_input) (s : seed) :
  le_real_execution_semantic_rejection_ticket distr =
  dmap d_le_real_execution_semantic_rejection_decision_choice
    (fun decision =>
      le_real_execution_semantic_rejection_ticket_of_observable_branch x s
        (le_real_execution_observable x s) decision.`leresd_reject).

op le_real_execution_semantic_rejection_ticket_requires_repair
  (ticket : le_real_execution_semantic_rejection_ticket) : bool =
  ticket.`lerest_decision.`leresd_repairs_hidden_query_material.

lemma le_real_execution_semantic_rejection_ticket_of_category_decisionE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category)).`lerest_decision =
  le_real_execution_semantic_rejection_decision_of_category category.
proof.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
by rewrite /le_real_execution_semantic_rejection_decision_of_category
  /le_real_execution_semantic_rejection_category_is_failure.
qed.

lemma le_real_execution_semantic_rejection_ticket_of_category_requires_repairE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_real_execution_semantic_rejection_ticket_requires_repair
    (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
      (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category)) =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite /le_real_execution_semantic_rejection_ticket_requires_repair.
rewrite (le_real_execution_semantic_rejection_ticket_of_category_decisionE x s obs category).
exact
  (le_real_execution_semantic_rejection_decision_of_category_repairs_hidden_query_materialE
    category).
qed.

lemma le_real_execution_semantic_rejection_ticket_of_category_branch_bitE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category)).`lerest_challenge_seed_material.`lerecsm_branch =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
by rewrite /le_real_execution_semantic_rejection_challenge_seed_material_of_branch.
qed.

lemma le_real_execution_semantic_rejection_failure_category_query_material_matches_challenge_seed_obsE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category =>
  (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category)).`lerest_query_material.`leqm_row_challenge_seed =
  le_real_execution_semantic_rejection_challenge_seed_obs_of_branch x s true.
proof.
move=> Hfail.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch.
by rewrite Hfail /=.
qed.

lemma le_real_execution_semantic_rejection_failure_category_query_material_matches_programmed_query_digest_obsE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category =>
  (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure category)).`lerest_query_material.`leqm_row_programmed_query_digest =
  le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch x s true.
proof.
move=> Hfail.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch.
by rewrite Hfail /=.
qed.

lemma le_real_execution_semantic_rejection_accept_category_query_material_idE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_real_execution_semantic_rejection_ticket_of_observable_branch x s obs
    (BudgetParameters.le_rejection_semantic_ticket_category_is_failure
      BudgetParameters.LERejectionSemanticTicketAccept)).`lerest_query_material =
  obs.`leto_query_material.
proof.
rewrite /le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /BudgetParameters.le_rejection_semantic_ticket_category_is_failure /pred1.
by rewrite /le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch /=.
qed.

op d_le_real_execution_semantic_rejection_ticket_repair_choice
  (x : qssm_public_input) (s : seed) : bool distr =
  dmap (d_le_real_execution_semantic_rejection_ticket_choice x s)
    le_real_execution_semantic_rejection_ticket_requires_repair.

lemma d_le_real_execution_semantic_rejection_ticket_choice_projects_branch
  (x : qssm_public_input) (s : seed) :
  dmap (d_le_real_execution_semantic_rejection_ticket_choice x s)
    (fun ticket => ticket.`lerest_decision.`leresd_reject) =
  d_le_real_execution_semantic_rejection_branch_choice.
proof.
rewrite /d_le_real_execution_semantic_rejection_ticket_choice.
rewrite (dmap_comp
  (fun decision =>
    le_real_execution_semantic_rejection_ticket_of_observable_branch x s
      (le_real_execution_observable x s) decision.`leresd_reject)
  (fun ticket => ticket.`lerest_decision.`leresd_reject)
  d_le_real_execution_semantic_rejection_decision_choice).
have Hmap :
  dmap d_le_real_execution_semantic_rejection_decision_choice
    ((fun ticket => ticket.`lerest_decision.`leresd_reject) \o
      (fun decision =>
        le_real_execution_semantic_rejection_ticket_of_observable_branch x s
          (le_real_execution_observable x s) decision.`leresd_reject)) =
  dmap d_le_real_execution_semantic_rejection_decision_choice
    le_real_execution_semantic_rejection_decision_reject.
  apply eq_dmap_in=> decision _ /=.
  by rewrite /le_real_execution_semantic_rejection_decision_reject /(\o)
    /le_real_execution_semantic_rejection_ticket_of_observable_branch.
rewrite Hmap.
by rewrite /d_le_real_execution_semantic_rejection_branch_choice.
qed.

lemma d_le_real_execution_semantic_rejection_ticket_choice_projects_repair
  (x : qssm_public_input) (s : seed) :
  d_le_real_execution_semantic_rejection_ticket_repair_choice x s =
  d_le_real_execution_semantic_rejection_decision_repair_choice.
proof.
rewrite /d_le_real_execution_semantic_rejection_ticket_repair_choice.
rewrite /d_le_real_execution_semantic_rejection_ticket_choice.
rewrite (dmap_comp
  (fun decision =>
    le_real_execution_semantic_rejection_ticket_of_observable_branch x s
      (le_real_execution_observable x s) decision.`leresd_reject)
  le_real_execution_semantic_rejection_ticket_requires_repair
  d_le_real_execution_semantic_rejection_decision_choice).
have Hmap :
  dmap d_le_real_execution_semantic_rejection_decision_choice
    (le_real_execution_semantic_rejection_ticket_requires_repair \o
      (fun decision =>
        le_real_execution_semantic_rejection_ticket_of_observable_branch x s
          (le_real_execution_observable x s) decision.`leresd_reject)) =
  dmap d_le_real_execution_semantic_rejection_decision_choice
    le_real_execution_semantic_rejection_decision_repairs_hidden_query_material.
  apply eq_dmap_in=> decision Hdecision /=.
  rewrite /le_real_execution_semantic_rejection_ticket_requires_repair /(\o)
    /le_real_execution_semantic_rejection_ticket_of_observable_branch
    /le_real_execution_semantic_rejection_decision_repairs_hidden_query_material.
  have Hrepair :
      decision.`leresd_repairs_hidden_query_material = decision.`leresd_reject.
    exact
      (le_real_execution_semantic_rejection_decision_choice_support_repairs_hidden_query_materialE
        decision Hdecision).
  by rewrite eq_sym Hrepair.
rewrite Hmap.
by [].
qed.

lemma d_le_real_execution_semantic_rejection_ticket_repair_choiceE
  (x : qssm_public_input) (s : seed) :
  d_le_real_execution_semantic_rejection_ticket_repair_choice x s =
  BudgetParameters.d_le_rejection_semantic_ticket_repair_choice.
proof.
rewrite (d_le_real_execution_semantic_rejection_ticket_choice_projects_repair x s).
exact d_le_real_execution_semantic_rejection_decision_repair_choiceE.
qed.

op le_real_execution_semantic_rejection_ticket_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  mu1 (d_le_real_execution_semantic_rejection_ticket_repair_choice x s) true.

lemma le_real_execution_semantic_rejection_ticket_failure_probability_eq_ticket_failure_law
  (x : qssm_public_input) (s : seed) :
  le_real_execution_semantic_rejection_ticket_failure_probability x s =
  BudgetParameters.le_rejection_semantic_ticket_failure_probability.
proof.
rewrite /le_real_execution_semantic_rejection_ticket_failure_probability.
rewrite (d_le_real_execution_semantic_rejection_ticket_repair_choiceE x s).
by rewrite /BudgetParameters.le_rejection_semantic_ticket_failure_probability.
qed.

lemma le_real_execution_semantic_rejection_ticket_failure_probability_eq_epsilon_le_rej_semantic
  (x : qssm_public_input) (s : seed) :
  le_real_execution_semantic_rejection_ticket_failure_probability x s =
  BudgetParameters.epsilon_le_rej_semantic.
proof.
rewrite le_real_execution_semantic_rejection_ticket_failure_probability_eq_ticket_failure_law.
exact BudgetParameters.epsilon_le_rej_semantic_is_ticket_failure_probability.
qed.

lemma le_real_execution_primitive_material_exposes_challenge_seed_material :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_primitive_material_of x s).`lerem_challenge_seed_material =
      le_real_execution_challenge_seed_material_of x s.
proof.
by move=> x s; rewrite /le_real_execution_primitive_material_of.
qed.

lemma le_real_execution_primitive_material_exposes_programmed_query_digest_material :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_primitive_material_of x s).`lerem_programmed_query_digest_material =
      le_real_execution_programmed_query_digest_material_of x s.
proof.
by move=> x s; rewrite /le_real_execution_primitive_material_of.
qed.

lemma le_real_execution_observable_exposes_commitment_coeffs :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_commitment_coeffs =
      le_real_execution_commitment_coeffs x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_commitment_coeffs.
qed.

lemma le_real_execution_observable_exposes_t_coeffs :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_t_coeffs =
      le_real_execution_t_coeffs x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_t_coeffs.
qed.

lemma le_real_execution_observable_exposes_z_coeffs :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_z_coeffs =
      le_real_execution_z_coeffs x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_z_coeffs.
qed.

lemma le_real_execution_observable_exposes_challenge_seed_obs :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_challenge_seed_obs =
      le_real_execution_challenge_seed_obs x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_challenge_seed_obs.
qed.

lemma le_real_execution_observable_exposes_programmed_query_digest_obs :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_programmed_query_digest_obs =
      le_real_execution_programmed_query_digest_obs x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_programmed_query_digest_obs.
qed.

lemma le_real_execution_observable_exposes_query_material :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_query_material =
      le_real_execution_query_material x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_query_material.
qed.

lemma le_real_execution_observable_exposes_qssm_event_payload :
  forall (x : qssm_public_input) (s : seed),
    (le_real_execution_observable x s).`leto_qssm_event_payload =
      le_real_execution_qssm_event_payload x s.
proof.
by move=> x s; rewrite /le_real_execution_observable /le_real_execution_qssm_event_payload.
qed.