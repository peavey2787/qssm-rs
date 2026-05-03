require import AllCore List Distr.
require import QssmTypes.
require import SourceConstructors.
require import SourcePayloadDistributions.
require import SourceCouplingTypes.

(* Hook file for **narrow** marginal bridges once `d_ms3a_seed_spine_joint` is tied to
   games: e.g. `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer =
   d_ms3a_real_payload_seed x` (and sim). Without such bridges, the four
   `A_ms3a_seed_pair_*_source_shared` axioms remain on **marginal** supports, not on the
   spine joint alone (`SourcePublicFieldObligations.ec`).

   `ms3a_ax_seed_coupling_pair_relation` is **not** unconditional: it holds when every
   spine draw on support is `ms3a_source_wf` — lemma
   `L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf` in `SourceCouplingTheorem.ec`. *)

lemma L_ms3a_real_sim_payload_seed_coupling_unfold (x : ms_public_input) (s : seed) :
  d_ms3a_real_sim_payload_seed_coupling x s =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_sim_seed_pair_of_bitness_layer.
proof.
by rewrite /d_ms3a_real_sim_payload_seed_coupling.
qed.
