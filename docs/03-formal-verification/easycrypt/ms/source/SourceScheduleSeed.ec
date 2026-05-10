require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.
require import SourcePayloadDistributions.
require import SourceBitnessDistributions.

(* Seed schedule: **proved** from narrow spine marginal bridges
   (`A_ms3a_spine_{real,sim}_marginal_matches_seed` in `SourcePayloadDistributions.ec`) by
   folding nested `dmap`s (`dmap_comp`) and `eq_dmap_in` with definitional inversion on the
   spine record (same six-field round-trip as
   `L_ms3a_bitness_layer_of_{real,sim}_payload_seed_of_bitness` in `SourceConstructors.ec`). *)

lemma A_ms3a_bitness_layer_seed_schedule (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload.
proof.
rewrite -(A_ms3a_spine_real_marginal_matches_seed x s)
  -(A_ms3a_spine_sim_marginal_matches_seed x s).
rewrite (dmap_comp ms3a_real_payload_seed_of_bitness_layer
  ms3a_bitness_layer_source_of_real_payload (d_ms3a_seed_spine_joint x s)).
rewrite (dmap_comp ms3a_sim_payload_seed_of_bitness_layer
  ms3a_bitness_layer_source_of_sim_payload (d_ms3a_seed_spine_joint x s)).
apply eq_dmap_in=> src _ /=.
case: src=> ms3s_stmt ms3s_result ms3s_bits ms3s_bitness_global_challenges
  ms3s_comparison_global_challenge ms3s_transcript_digest.
by rewrite /ms3a_bitness_layer_source_of_real_payload /ms3a_real_payload_seed_of_bitness_layer
  /ms3a_bitness_layer_source_of_sim_payload /ms3a_sim_payload_seed_of_bitness_layer
  /ms3a_make_real_source /ms3a_make_sim_source /=.
qed.

lemma L_ms3a_bitness_layer_seed_schedule_composed_form (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_payload_seed x)
    (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed x) =
  dmap (d_ms3a_sim_payload_seed x s)
    (ms3a_bitness_layer_source_of_sim_payload \o ms3a_sim_payload_from_seed x s).
proof.
rewrite (L_ms3a_bitness_layer_seed_push_real_eq_layer_dmap x)
  (L_ms3a_bitness_layer_seed_push_sim_eq_layer_dmap x s).
exact (A_ms3a_bitness_layer_seed_schedule x s).
qed.
