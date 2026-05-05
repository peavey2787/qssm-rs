require import QssmTypes Domains FS SourceModel.
require import AllCore List Distr.

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

op le_real_execution_hidden_query_material_of
  (x : qssm_public_input) (s : seed) : le_query_material = tt.

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