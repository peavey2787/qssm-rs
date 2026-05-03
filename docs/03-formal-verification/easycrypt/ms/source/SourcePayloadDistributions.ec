require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceConstructors.

(* Abstract seed laws and payload-level `dmap` pushforwards (MS-3a). *)

(* Structured joint spine: one draw of `ms3a_bitness_layer_source` per `(x,s)`; real/sim
   typed seeds are definitional copies (`SourceConstructors.ec`). Narrow marginal-bridge
   axioms `A_ms3a_spine_real_marginal_matches_seed` and `A_ms3a_spine_sim_marginal_matches_seed`
   relate those `dmap` marginals to the abstract seed laws; games / linking still supply
   `d_ms3a_seed_spine_joint` and discharge the bridges (plus `A_ms3a_seed_spine_support_wf`,
   `A_ms3a_spine_marginal_pair_common_lift`). *)
op d_ms3a_seed_spine_joint (x : ms_public_input) (s : seed) : ms3a_bitness_layer_source distr.

op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr.
op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).

(* ------------------------------------------------------------------------- *)
(* Spine ↔ marginal bridges (narrow obligations for game / linking discharge). *)

axiom A_ms3a_spine_real_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer =
  d_ms3a_real_payload_seed x.

axiom A_ms3a_spine_sim_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer =
  d_ms3a_sim_payload_seed x s.

axiom A_ms3a_seed_spine_support_wf (x : ms_public_input) (s : seed) :
  forall (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s => ms3a_source_wf src.

(* Same-spine lift for arbitrary marginal pairs: game-level “one draw, two projections”
   residue. Together with `L_ms3a_payload_pair_public_fields_seed_of_bitness` it discharges
   the four `A_ms3a_seed_pair_*_source_shared` lemmas in `SourcePublicFieldObligations.ec`. *)
axiom A_ms3a_spine_marginal_pair_common_lift (x : ms_public_input) (s : seed)
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  exists (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s /\
    ms3a_real_payload_seed_of_bitness_layer src = sr /\
    ms3a_sim_payload_seed_of_bitness_layer src = ss.
