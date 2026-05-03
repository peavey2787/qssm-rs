require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceTypes SourcePayloadDistributions SourceConstructors.

(* MS-3a seed coupling: structured joint
   `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer`
   (one shared `ms3a_bitness_layer_source` spine per (x,s); real/sim typed seeds are
   definitional copies of the same six fields).

   This is not the independent product of `d_ms3a_real_payload_seed` and
   `d_ms3a_sim_payload_seed`: those laws remain abstract until games instantiate them.
   Marginal bridge axioms `A_ms3a_spine_real_marginal_matches_seed` and
   `A_ms3a_spine_sim_marginal_matches_seed` in `SourcePayloadDistributions.ec` state the
   intended real/sim marginal equalities against `d_ms3a_seed_spine_joint`.

   Pair relation (SourceCouplingTheorem.ec): on spine support, if every drawn spine
   satisfies `ms3a_source_wf`, then every pair in the joint satisfies
   `ms3a_real_sim_payload_seed_coupled`.

   Discharge map: the four `A_ms3a_seed_pair_*_source_shared` lemmas in
   SourcePublicFieldObligations.ec use axiom `A_ms3a_spine_marginal_pair_common_lift` so
   arbitrary marginal-support pairs share one spine preimage, plus field lemmas
   `L_ms3a_payload_pair_*_seed_of_bitness`. Lemma `A_ms3a_bitness_layer_seed_schedule` in
   SourceScheduleSeed.ec is proved from the two marginal bridge axioms using
   `dmap_comp` and `eq_dmap_in` (same six-field round-trip as
   `L_ms3a_bitness_layer_of_real_payload_seed_of_bitness` /
   `L_ms3a_bitness_layer_of_sim_payload_seed_of_bitness`). *)

pred ms3a_real_sim_payload_seed_coupled
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) =
  ms3a_payload_pair_public_fields_match sr ss /\
  sr.`ms3rp_bits = ss.`ms3sp_bits /\
  sr.`ms3rp_transcript_digest = ss.`ms3sp_transcript_digest /\
  ms_bitness_vector_programmed_layer
    sr.`ms3rp_stmt sr.`ms3rp_bits sr.`ms3rp_bitness_global_challenges /\
  ms_bitness_vector_programmed_layer
    ss.`ms3sp_stmt ss.`ms3sp_bits ss.`ms3sp_bitness_global_challenges.

op d_ms3a_real_sim_payload_seed_coupling (x : ms_public_input) (s : seed) :
  (ms3a_real_payload_seed * ms3a_sim_payload_seed) distr =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer.

op d_ms3a_coupling_seed_real_projection (x : ms_public_input) (s : seed) :
  ms3a_real_payload_seed distr =
  dmap (d_ms3a_real_sim_payload_seed_coupling x s) fst.

op d_ms3a_coupling_seed_sim_projection (x : ms_public_input) (s : seed) :
  ms3a_sim_payload_seed distr =
  dmap (d_ms3a_real_sim_payload_seed_coupling x s) snd.

(* Quantification over pairs drawn from the product coupling (support-only packaging). *)
pred ms3a_ax_seed_coupling_pair_relation (x : ms_public_input) (s : seed) =
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    (sr, ss) \in d_ms3a_real_sim_payload_seed_coupling x s =>
    ms3a_real_sim_payload_seed_coupled sr ss.

pred ms3a_ax_seed_support_coupling (x : ms_public_input) (s : seed) =
  d_ms3a_coupling_seed_real_projection x s = d_ms3a_real_payload_seed x /\
  d_ms3a_coupling_seed_sim_projection x s = d_ms3a_sim_payload_seed x s /\
  ms3a_ax_seed_coupling_pair_relation x s.
