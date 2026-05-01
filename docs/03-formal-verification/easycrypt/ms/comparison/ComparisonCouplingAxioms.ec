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

(* Product coupling: fst/snd marginals match standalone laws when the opposite
   marginal is lossless (dprod_marginalL / dprod_marginalR in Distr).
   Payload-law losslessness: lemmas L_ms3c_real_comparison_payload_law_lossless and
   L_ms3c_sim_comparison_payload_law_lossless in ComparisonPayloads.ec via dmap_ll from
   L_ms3c_real_payload_seed_lossless / L_ms3c_sim_payload_seed_lossless (dprod_ll_auto
   from the four component axioms A_ms3c_*_seed_{challenge,announcement}_lossless). *)

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

(* `A_ms3c_payload_schedule_eq_from_coupling` is a proved lemma in
   `ComparisonCouplingTheorem.ec`: bundled marginal correctness + pair relation on
   `d_ms3c_real_sim_payload_coupling` support force coupled payloads to be equal
   (`L_ms3c_payload_eq_of_coupled`), hence `dmap coupling fst = dmap coupling snd`
   (`eq_dmap_in`). *)
