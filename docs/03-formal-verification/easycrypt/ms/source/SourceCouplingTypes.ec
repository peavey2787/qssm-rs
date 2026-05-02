require import AllCore List Distr.
require import QssmTypes BitnessVector.
require import SourceTypes SourcePayloadDistributions.

(* MS-3a seed coupling scaffold (parallel to `ComparisonCouplingTypes.ec` on the
   comparison lane). Joint law is the **independent product** of the abstract seed
   laws `d_ms3a_real_payload_seed` and `d_ms3a_sim_payload_seed` (`SourcePayloadDistributions.ec`).
   Fst/snd marginals match those laws under `is_lossless` on the opposite factor
   (`SourceCouplingTheorem.ec`, same `dprod_marginal` pattern as MS-3c).

   **Discharge map for the nine `ms/source` seed axioms:** the four
   `A_ms3a_seed_pair_*_source_shared` axioms (`SourcePublicFieldObligations.ec`) are
   *pairing* facts on joint seed support; they are **not** implied by the product
   alone. A future **correlated** joint law refining `d_ms3a_real_sim_payload_seed_coupling`
   should prove `ms3a_ax_seed_coupling_pair_relation` / stronger support coupling, then
   recover `source_shared` via `supp_dmap`-style reasoning (cf. MS-3c schedule lemmas).
   The schedule axiom **`A_ms3a_bitness_layer_seed_schedule`** (`SourceScheduleObligations.ec`)
   needs **semantic** agreement of real vs sim seeds on **all six** fields (including
   `bits` and transcript digest); `ms3a_real_sim_payload_seed_coupled` packages exactly
   that alignment plus programmed bitness-vector premises on **both** sides, matching
   the programmed-on-support axioms (`SourceProgrammedObligations.ec`). *)

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
  d_ms3a_real_payload_seed x `*` d_ms3a_sim_payload_seed x s.

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
