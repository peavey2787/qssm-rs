require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloads.

(* Scheduling coupling layer: source/payload transport only (not cryptographic). *)
pred ms3c_real_sim_payload_coupled
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  ms3c_payload_pair_public_fields_match pr ps /\
  ms3c_payload_pair_challenge_shares_match pr ps /\
  ms3c_clause_ann_digests_from_surface (ms3c_make_real_clause_surface pr) =
  ms3c_clause_ann_digests_from_surface (ms3c_make_sim_clause_surface ps) /\
  ms_false_clause_simulated (ms3c_make_real_clause_surface pr) /\
  ms_false_clause_simulated (ms3c_make_sim_clause_surface ps).

op d_ms3c_real_sim_payload_coupling
  (x : ms_public_input) (s : seed) :
  (ms3c_real_comparison_payload * ms3c_sim_comparison_payload) distr.

op d_ms3c_coupling_real_projection (x : ms_public_input) (s : seed) :
  ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) fst.

op d_ms3c_coupling_sim_projection (x : ms_public_input) (s : seed) :
  ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) snd.

pred ms3c_ax_payload_coupling_pair_relation (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    (pr, ps) \in d_ms3c_real_sim_payload_coupling x s =>
    ms3c_real_sim_payload_coupled pr ps).

pred ms3c_ax_payload_support_coupling (x : ms_public_input) (s : seed) =
  d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x /\
  d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s /\
  ms3c_ax_payload_coupling_pair_relation x s.
