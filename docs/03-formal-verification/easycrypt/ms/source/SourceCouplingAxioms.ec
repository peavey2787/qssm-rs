require import AllCore List Distr.
require import QssmTypes.
require import SourcePayloadDistributions.
require import SourceCouplingTypes.

(* Hook file for **narrow** MS-3a seed-coupling obligations once `d_ms3a_*_payload_seed`
   are instantiated from games / execution (replacing the abstract product scaffold).

   Do **not** assert `ms3a_ax_seed_coupling_pair_relation` for the current product law
   together with the strong `ms3a_real_sim_payload_seed_coupled` predicate unless the
   joint law is refined: independent sampling does not correlate `bits`, digest, or
   programmed-vector witnesses across the real/sim components.

   Intended uses: (i) fragment lemmas packaging game-level invariants into
   `ms3a_ax_seed_support_coupling`; (ii) bridges from correlated joint support to the
   four `A_ms3a_seed_pair_*_source_shared` axioms and to schedule reasoning for
   `A_ms3a_bitness_layer_seed_schedule`. *)

lemma L_ms3a_real_sim_payload_seed_coupling_unfold (x : ms_public_input) (s : seed) :
  d_ms3a_real_sim_payload_seed_coupling x s =
  d_ms3a_real_payload_seed x `*` d_ms3a_sim_payload_seed x s.
proof.
by rewrite /d_ms3a_real_sim_payload_seed_coupling.
qed.
