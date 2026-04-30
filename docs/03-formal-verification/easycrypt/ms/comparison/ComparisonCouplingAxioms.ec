require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCouplingTypes.

(* Narrow payload obligations (still proof debt until laws are instantiated). *)
axiom A_ms3c_payload_public_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_public_fields_match x s.

axiom A_ms3c_payload_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_shares_match x s.

axiom A_ms3c_coupling_real_marginal :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x.

axiom A_ms3c_coupling_sim_marginal :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s.

axiom A_ms3c_coupling_pair_relation :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_coupling_pair_relation x s.

axiom A_ms3c_payload_schedule_eq_from_coupling :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_support_coupling x s =>
    d_ms3c_real_comparison_payload x = d_ms3c_sim_comparison_payload x s.
