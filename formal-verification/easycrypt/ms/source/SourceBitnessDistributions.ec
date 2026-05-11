require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceConstructors BitnessOne.
require import SourcePayloadDistributions.

(* Bitness-layer sources: pushforward of payload laws through constructor maps. *)
op d_ms3a_bitness_real_source (x : ms_public_input) : ms3a_bitness_layer_source distr =
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload.

op d_ms3a_bitness_sim_source (x : ms_public_input) (s : seed) :
  ms3a_bitness_layer_source distr =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.

(* Fold nested payload `dmap`s to a single `dmap` off seed laws (`Distr.dmap_comp`). *)
lemma ms3a_bitness_real_source_as_seed_dmap (x : ms_public_input) :
  d_ms3a_bitness_real_source x =
  dmap (d_ms3a_real_payload_seed x)
    (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed x).
proof.
rewrite /d_ms3a_bitness_real_source /d_ms3a_real_source_payload.
by rewrite (dmap_comp (ms3a_real_payload_from_seed x)
  ms3a_bitness_layer_source_of_real_payload (d_ms3a_real_payload_seed x)).
qed.

lemma ms3a_bitness_sim_source_as_seed_dmap (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_sim_source x s =
  dmap (d_ms3a_sim_payload_seed x s)
    (ms3a_bitness_layer_source_of_sim_payload \o ms3a_sim_payload_from_seed x s).
proof.
rewrite /d_ms3a_bitness_sim_source /d_ms3a_sim_source_payload.
by rewrite (dmap_comp (ms3a_sim_payload_from_seed x s)
  ms3a_bitness_layer_source_of_sim_payload (d_ms3a_sim_payload_seed x s)).
qed.

(* `from_seed` is the identity on payload-shaped seeds (`SourceConstructors.ec`); the
   composed map in the legacy schedule statement extensionally equals the layer map. *)
lemma L_ms3a_bitness_layer_seed_push_real_eq_layer_dmap (x : ms_public_input) :
  dmap (d_ms3a_real_payload_seed x)
    (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed x) =
  dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload.
proof. by apply eq_dmap_in=> sigma _ /=. qed.

lemma L_ms3a_bitness_layer_seed_push_sim_eq_layer_dmap (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_sim_payload_seed x s)
    (ms3a_bitness_layer_source_of_sim_payload \o ms3a_sim_payload_from_seed x s) =
  dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload.
proof. by apply eq_dmap_in=> sigma _ /=. qed.
