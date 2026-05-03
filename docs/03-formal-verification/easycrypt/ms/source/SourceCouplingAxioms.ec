require import AllCore List Distr.
require import QssmTypes.
require import SourceConstructors.
require import SourcePayloadDistributions.
require import SourceCouplingTypes.

(* Narrow marginal bridge axioms live in SourcePayloadDistributions.ec
   (A_ms3a_spine_real_marginal_matches_seed, A_ms3a_spine_sim_marginal_matches_seed,
   A_ms3a_seed_spine_support_wf, A_ms3a_spine_marginal_pair_common_lift) for game-level
   discharge once d_ms3a_seed_spine_joint is instantiated. The four
   A_ms3a_seed_pair_*_source_shared statements are proved lemmas in
   SourcePublicFieldObligations.ec from the common-lift axiom plus
   L_ms3a_payload_pair_public_fields_seed_of_bitness.

   ms3a_ax_seed_coupling_pair_relation is not unconditional: it holds when every
   spine draw on support is ms3a_source_wf — lemma
   L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf in SourceCouplingTheorem.ec. *)

lemma L_ms3a_real_sim_payload_seed_coupling_unfold (x : ms_public_input) (s : seed) :
  d_ms3a_real_sim_payload_seed_coupling x s =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer.
proof.
by rewrite /d_ms3a_real_sim_payload_seed_coupling.
qed.
