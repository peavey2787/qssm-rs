require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceModel SourceConstructors.

(* Abstract seed laws and payload-level `dmap` pushforwards (MS-3a). *)

(* Structured joint spine: one draw of `ms3a_bitness_layer_source` per `(x,s)`; real/sim
   typed seeds are definitional copies (`SourceConstructors.ec`).

   **Sim payload seed law** is the **spine sim marginal** by definition (same `(x,s)` as the
   joint). The **real** law stays abstract: its type has no `s`, so it cannot be defined as
   `dmap (d_ms3a_seed_spine_joint x s) …` without either (i) a separate proof that that
   `dmap` is independent of `s`, or (ii) extending the interface with `s`. Narrow axiom
  `A_ms3a_spine_real_marginal_matches_seed` still ties the abstract real law to the joint’s
  real marginal for every `s`. Games / linking still supply `d_ms3a_seed_spine_joint` and
  the real bridge plus `A_ms3a_seed_spine_support_wf` and the narrower paired-public-fields
  support obligation below. *)
op d_ms3a_seed_spine_joint (x : ms_public_input) (s : seed) : ms3a_bitness_layer_source distr.

(* MS-3a real payload seed law. Definitional point mass at the canonical public spine,
   pushed forward to the real payload-seed type. This matches the concrete execution-seed
   law `d_ms3a_real_execution_public_seed` defined in `SourceRealExecutionGameLink.ec`,
   keeping a single canonical real-law surface (Option A; the previous bridge axiom
   `A_ms3a_real_payload_seed_matches_execution_seed` is now a proved lemma). *)
op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr =
  dmap
    (dunit (ms3a_make_real_source
       (ms3a_public_stmt_digest x)
       (ms3a_public_result_bit x)
       (ms3a_public_bits x)
       (ms3a_public_bitness_globals x)
       (ms3a_public_comparison_global x)
       (ms3a_public_transcript_digest x)))
    ms3a_real_payload_seed_of_bitness_layer.

op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).

(* ------------------------------------------------------------------------- *)
(* Spine ↔ marginal bridges (narrow obligations for game / linking discharge).
   `d_ms3a_sim_payload_seed` is defined as the joint sim marginal; lemma
   `A_ms3a_spine_sim_marginal_matches_seed` is definitional packaging (keeps schedule proofs
   unchanged). The joint and real seed law remain abstract: no proof of the real bridge, WF,
  or support-level paired-public alignment at this layer without game-level definitions or
  further axioms. *)

axiom A_ms3a_spine_real_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer =
  d_ms3a_real_payload_seed x.

lemma A_ms3a_spine_sim_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer =
  d_ms3a_sim_payload_seed x s.
proof. by []. qed.

axiom A_ms3a_seed_spine_support_wf (x : ms_public_input) (s : seed) :
  forall (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s => ms3a_source_wf src.

(* Narrow paired-public consequence still needed downstream: arbitrary support elements from the
   abstract real and sim seed laws agree on the four shared public fields. This is strictly
   weaker than a same-spine witness obligation and is the only consequence currently consumed by
   `SourcePublicFieldObligations.ec`. *)
axiom A_ms3a_seed_pair_public_fields_match_on_support (x : ms_public_input) (s : seed)
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  ms3a_payload_pair_public_fields_match sr ss.
