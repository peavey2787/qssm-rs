require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceConstructors.

(* Abstract seed laws and payload-level `dmap` pushforwards (MS-3a). *)

(* Structured joint spine: one draw of `ms3a_bitness_layer_source` per `(x,s)`; real/sim
   seeds are definitional copies (`SourceConstructors.ec`). **No** marginal identity with
   `d_ms3a_{real,sim}_payload_seed` is asserted here — those laws stay independent abstract
   interfaces until games / linking supply `d_ms3a_seed_spine_joint` and marginal bridges. *)
op d_ms3a_seed_spine_joint (x : ms_public_input) (s : seed) : ms3a_bitness_layer_source distr.

op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr.
op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).
