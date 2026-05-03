require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes SourceModel SourceConstructors.

(* Abstract seed laws and payload-level `dmap` pushforwards (MS-3a). *)

(* Canonical execution source on the public spine. Used as the underlying point mass for both
   the spine joint and the real/sim seed laws below, so all three become definitional copies of
   the same canonical record. *)
op ms3a_canonical_public_source (x : ms_public_input) : ms3a_bitness_layer_source =
  ms3a_make_real_source
    (ms3a_public_stmt_digest x)
    (ms3a_public_result_bit x)
    (ms3a_public_bits x)
    (ms3a_public_bitness_globals x)
    (ms3a_public_comparison_global x)
    (ms3a_public_transcript_digest x).

(* Structured joint spine: now a definitional point mass at the canonical public-spine source
   (same record used by `d_ms3a_real_payload_seed` below). With this definition the previous
   axioms `A_ms3a_spine_real_marginal_matches_seed` and
   `A_ms3a_seed_pair_public_fields_match_on_support` are now proved lemmas. The remaining
   axiom `A_ms3a_seed_spine_support_wf` simplifies to `ms3a_source_wf` of the canonical source
   on the singleton support, and is the lone primitive carrying the abstract programmed-bitness
   fact about the public spine. *)
op d_ms3a_seed_spine_joint (x : ms_public_input) (_s : seed) : ms3a_bitness_layer_source distr =
  dunit (ms3a_canonical_public_source x).

(* MS-3a real payload seed law. Definitional `dmap` of `dunit` at the canonical public spine,
   matching `d_ms3a_real_execution_public_seed` (`SourceRealExecutionGameLink.ec`)
   definitionally; bridge `A_ms3a_real_payload_seed_matches_execution_seed` is a proved
   lemma in `SourceRealExecutionSeed.ec`. *)
op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr =
  dmap (dunit (ms3a_canonical_public_source x))
    ms3a_real_payload_seed_of_bitness_layer.

op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).

(* ------------------------------------------------------------------------- *)
(* Spine ↔ marginal bridges. With the canonical-source spine, both real-marginal and
   paired-public-fields obligations are now proved lemmas; only the spine-support
   well-formedness axiom remains, and it is now the singleton fact
   `ms3a_source_wf (ms3a_canonical_public_source x)`. *)

lemma A_ms3a_spine_real_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer =
  d_ms3a_real_payload_seed x.
proof.
by rewrite /d_ms3a_seed_spine_joint /d_ms3a_real_payload_seed.
qed.

lemma A_ms3a_spine_sim_marginal_matches_seed (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer =
  d_ms3a_sim_payload_seed x s.
proof. by []. qed.

axiom A_ms3a_seed_spine_support_wf (x : ms_public_input) (s : seed) :
  forall (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s => ms3a_source_wf src.

(* Narrow paired-public consequence: now provable from the canonical-source spine, because
   both seed laws are point masses at the real/sim images of the same canonical source, and
   `L_ms3a_payload_pair_public_fields_seed_of_bitness` already discharges paired-public
   fields for any single source. *)
lemma A_ms3a_seed_pair_public_fields_match_on_support (x : ms_public_input) (s : seed)
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  ms3a_payload_pair_public_fields_match sr ss.
proof.
rewrite /d_ms3a_real_payload_seed /d_ms3a_sim_payload_seed
  /d_ms3a_seed_spine_joint.
move=> /supp_dmap [src1 [+ Hsr]] /supp_dmap [src2 [+ Hss]].
rewrite !supp_dunit => Hsrc1 Hsrc2.
rewrite Hsr Hss Hsrc1 Hsrc2.
exact (L_ms3a_payload_pair_public_fields_seed_of_bitness
  (ms3a_canonical_public_source x)).
qed.
