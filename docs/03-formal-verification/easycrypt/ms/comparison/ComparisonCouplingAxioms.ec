require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCouplingTypes.

(* Field-level hook bridges: real vs sim payload laws are independent `dmap`
   pushforwards of abstract seeds (`ComparisonPayloadSeeds.ec`); matching public
   fields or challenge-share carriers on **cross-marginal** support is not
   derivable from the five hooks alone without instantiating
   `ms3c_{real,sim}_payload_from_seed`. Split by carrier fragment so games can
   discharge obligations incrementally. *)

axiom A_ms3c_payload_index_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_index_fields_match x s.

axiom A_ms3c_payload_ann_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_ann_fields_match x s.

axiom A_ms3c_payload_stmt_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_stmt_fields_match x s.

axiom A_ms3c_payload_result_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_result_fields_match x s.

lemma A_ms3c_payload_public_fields_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_public_fields_match x s.
proof.
move=> x s H1 H2 H3 H4 H5.
have Hix := A_ms3c_payload_index_fields_match x s H1 H2 H3 H4 H5.
have Hann := A_ms3c_payload_ann_fields_match x s H1 H2 H3 H4 H5.
have Hstmt := A_ms3c_payload_stmt_fields_match x s H1 H2 H3 H4 H5.
have Hres := A_ms3c_payload_result_fields_match x s H1 H2 H3 H4 H5.
exact (L_ms3c_ax_payload_public_fields_match_from_fragments x s Hix Hann Hstmt Hres).
qed.

axiom A_ms3c_payload_true_challenge_share_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_true_challenge_share_match x s.

axiom A_ms3c_payload_false_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_false_challenge_shares_match x s.

axiom A_ms3c_payload_challenge_share_lengths_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_share_lengths_match x s.

lemma A_ms3c_payload_challenge_shares_match :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    ms3c_ax_payload_challenge_shares_match x s.
proof.
move=> x s H1 H2 H3 H4 H5.
have Ht := A_ms3c_payload_true_challenge_share_match x s H1 H2 H3 H4 H5.
have Hf := A_ms3c_payload_false_challenge_shares_match x s H1 H2 H3 H4 H5.
have Hl := A_ms3c_payload_challenge_share_lengths_match x s H1 H2 H3 H4 H5.
exact (L_ms3c_ax_payload_challenge_shares_match_from_fragments x s Ht Hf Hl).
qed.

(* Product coupling: fst/snd marginals match standalone laws when the opposite
   marginal is lossless (dprod_marginalL / dprod_marginalR in Distr).
   Payload-law losslessness: lemmas L_ms3c_real_comparison_payload_law_lossless and
   L_ms3c_sim_comparison_payload_law_lossless in ComparisonPayload.ec via dmap_ll from
   L_ms3c_real_payload_seed_lossless / L_ms3c_sim_payload_seed_lossless (dprod_ll_auto
   from the four component axioms A_ms3c_*_seed_{challenge,announcement}_lossless).
   Predicate ms3c_ax_payload_announcements_match_shape is proved for all x,s as
   L_ms3c_ax_payload_announcements_match_shape_total (ComparisonPayload.ec), hence it
   is not a premise below. Likewise ms3c_ax_payload_announcement_digests_preserved
   follows from ms3c_ax_payload_public_fields_match via lemma
   L_ms3c_payload_announcement_digests_preserved_from_public_fields
   (ComparisonCouplingSchedule.ec), hence it is not a premise below.
   Pair-relation packaging **`A_ms3c_coupling_pair_relation`** is also a **proved
   lemma** there: independent-product support (`supp_dprod`) + the five
   `ms3c_ax_payload_*` predicates imply **`ms3c_real_sim_payload_coupled`** pointwise. *)

(* `A_ms3c_payload_schedule_eq_from_coupling` is a proved lemma in
   `ComparisonCouplingSchedule.ec`: bundled marginal correctness + pair relation on
   `d_ms3c_real_sim_payload_coupling` support force coupled payloads to be equal
   (`L_ms3c_payload_eq_of_coupled`), hence `dmap coupling fst = dmap coupling snd`
   (`eq_dmap_in`). *)
