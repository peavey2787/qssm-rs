require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceConstructors.

(* Abstract seed laws and payload-level `dmap` pushforwards (MS-3a). *)
op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr.
op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).
