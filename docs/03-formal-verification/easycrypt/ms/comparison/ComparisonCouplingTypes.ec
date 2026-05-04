require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload.

(* Scheduling coupling layer: source/payload transport only (not cryptographic).
  Joint law is the **independent product** of the abstract payload laws. Fst/snd
  marginals then match the standalone laws under **`is_lossless`** on the opposite
  law (see `ComparisonCouplingTheorem.ec`). Correlated behaviour for schedule
  equality still comes from lemma A_ms3c_coupling_pair_relation in
  ComparisonCouplingSchedule.ec (not implied by the product alone), but the
  pairwise layer now records explicit folded-surface agreement rather than relying
  on payload equality on support. *)

pred ms3c_payload_pair_surface_match
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  ms3c_make_real_clause_surface pr = ms3c_make_sim_clause_surface ps.

pred ms3c_real_sim_payload_coupled
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) =
  ms3c_payload_pair_public_fields_match pr ps /\
  ms3c_payload_pair_challenge_shares_match pr ps /\
  ms3c_payload_pair_surface_match pr ps /\
  ms_false_clause_simulated (ms3c_make_real_clause_surface pr) /\
  ms_false_clause_simulated (ms3c_make_sim_clause_surface ps).

op d_ms3c_real_sim_payload_coupling
  (x : ms_public_input) (s : seed) :
  (ms3c_real_comparison_payload * ms3c_sim_comparison_payload) distr =
  d_ms3c_real_comparison_payload x `*` d_ms3c_sim_comparison_payload x s.

op d_ms3c_coupling_real_projection (x : ms_public_input) (s : seed) :
  ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) fst.

op d_ms3c_coupling_sim_projection (x : ms_public_input) (s : seed) :
  ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_real_sim_payload_coupling x s) snd.

(* Support-only: quantification is over pairs in `d_ms3c_real_sim_payload_coupling`. *)
pred ms3c_ax_payload_coupling_pair_relation (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    (pr, ps) \in d_ms3c_real_sim_payload_coupling x s =>
    ms3c_real_sim_payload_coupled pr ps).

pred ms3c_ax_payload_support_coupling (x : ms_public_input) (s : seed) =
  d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x /\
  d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s /\
  ms3c_ax_payload_coupling_pair_relation x s.
