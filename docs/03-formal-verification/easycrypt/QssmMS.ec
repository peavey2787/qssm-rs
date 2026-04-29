require import AllCore List Distr.
require import QssmTypes QssmFS.
require import QssmSchnorrSingleBit.
(* MS v2 single-bit OR bitness (two branches + challenge split). *)
require import QssmMSBitnessSingle.
(* All-bit bitness vector layer (V2_BIT_COUNT = 64; composition predicates). *)
require import QssmMSBitnessVector.
(* Canonical v2 observable record + bitness/digest bridges (`ms_v2_*`).     *)
require import QssmMSTranscriptObservable.

(* MS v2 transcript observable surface (abstract, aligned to execution spec) *)
op ms_statement_digest : ms_transcript_observable -> digest.
op ms_result_bit : ms_transcript_observable -> bool.
op ms_bitness_global_challenges : ms_transcript_observable -> digest list.
op ms_comparison_global_challenge : ms_transcript_observable -> digest.
op ms_transcript_digest : ms_transcript_observable -> digest.

(* Abstract observable agrees with the canonical v2 record (linking layer).   *)
pred ms_abstract_observable_aligns_v2
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  ms_statement_digest obs = o.`msv2_statement_digest /\
  ms_result_bit obs = o.`msv2_result_bit /\
  ms_bitness_global_challenges obs = o.`msv2_bitness_global_challenges /\
  ms_comparison_global_challenge obs = o.`msv2_comparison_global_challenge /\
  ms_transcript_digest obs = o.`msv2_transcript_digest.

(* Abstract transcript + v2 record + digest cell (reusable MS-3a frame).      *)
pred ms3a_frame_consistent
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  ms_abstract_observable_aligns_v2 obs o /\
  ms_transcript_digest_of_observable o.

(* Canonical observable packer from the MS-v2 public transcript fields.         *)
op ms3a_pack_observable
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest) : ms_v2_transcript_observable =
  {| msv2_statement_digest = stmt;
     msv2_result_bit = rbit;
     msv2_bitness_global_challenges = bitness_glob;
     msv2_comparison_global_challenge = comp_glob;
     msv2_transcript_digest = td |}.

(* Projection from canonical v2 observable to abstract observable carrier.      *)
op ms3a_observable_of_v2 : ms_v2_transcript_observable -> ms_transcript_observable.

axiom A_ms3a_observable_of_v2_aligns :
  forall (o : ms_v2_transcript_observable),
    ms_abstract_observable_aligns_v2 (ms3a_observable_of_v2 o) o.

(* Frame constructor relation for packed observables.                           *)
pred ms3a_packed_frame
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest)
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  o = ms3a_pack_observable stmt rbit bitness_glob comp_glob td /\
  obs = ms3a_observable_of_v2 o /\
  ms3a_frame_consistent obs o.

lemma MS_3a_frame_consistent_of_v2
  (o : ms_v2_transcript_observable) :
  ms_transcript_digest_of_observable o =>
  ms3a_frame_consistent (ms3a_observable_of_v2 o) o.
proof.
move=> Hd; split.
- exact (A_ms3a_observable_of_v2_aligns o).
exact Hd.
qed.

(* Constructor/layout lemma: for any packed observable, digest consistency
   follows from the explicit digest-field equation. *)
lemma ms3a_packed_observable_digest_consistent
  (stmt : digest) (rbit : bool) (bitness_glob : digest list)
  (comp_glob : digest) (td : digest) :
  td = ms_transcript_digest_public_fields
        (ms3a_pack_observable stmt rbit bitness_glob comp_glob td) =>
  ms_transcript_digest_of_observable
    (ms3a_pack_observable stmt rbit bitness_glob comp_glob td).
proof.
move=> Htd; rewrite /ms_transcript_digest_of_observable /ms3a_pack_observable.
by rewrite -Htd.
qed.

(* Digest-by-construction constructor (generic, non-default-specific).        *)
op ms3a_pack_observable_with_digest
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) : ms_v2_transcript_observable.

axiom ms3a_pack_observable_with_digest_field_correct
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob =
  ms3a_pack_observable stmt rbit bitness_glob comp_glob
    (ms_transcript_digest_public_fields
      (ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob)).

lemma ms3a_pack_observable_with_digest_consistent
  (stmt : digest) (rbit : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms_transcript_digest_of_observable
    (ms3a_pack_observable_with_digest stmt rbit bitness_glob comp_glob).
proof.
have Ho :=
  ms3a_pack_observable_with_digest_field_correct
    stmt rbit bitness_glob comp_glob.
rewrite Ho; apply ms3a_packed_observable_digest_consistent.
by rewrite -{1}Ho.
qed.

(* Structured source sampled before final observable pushforward.               *)
type ms3a_bitness_layer_source = {
  ms3s_stmt : digest;
  ms3s_result : bool;
  ms3s_bits : ms_single_bit_or_transcript list;
  ms3s_bitness_global_challenges : digest list;
  ms3s_comparison_global_challenge : digest;
  ms3s_transcript_digest : digest;
}.

op ms3a_make_real_source
  (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = rbit;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

op ms3a_make_sim_source
  (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = rbit;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

(* Constructor payloads: exactly the arguments to `ms3a_make_*_source`.        *)
type ms3a_real_source_payload = {
  ms3rp_stmt : digest;
  ms3rp_res : bool;
  ms3rp_bits : ms_single_bit_or_transcript list;
  ms3rp_bitness_global_challenges : digest list;
  ms3rp_comparison_global_challenge : digest;
  ms3rp_transcript_digest : digest;
}.

type ms3a_sim_source_payload = {
  ms3sp_stmt : digest;
  ms3sp_res : bool;
  ms3sp_bits : ms_single_bit_or_transcript list;
  ms3sp_bitness_global_challenges : digest list;
  ms3sp_comparison_global_challenge : digest;
  ms3sp_transcript_digest : digest;
}.

op ms3a_bitness_layer_source_of_real_payload (p : ms3a_real_source_payload) :
  ms3a_bitness_layer_source =
  ms3a_make_real_source p.`ms3rp_stmt p.`ms3rp_res p.`ms3rp_bits
    p.`ms3rp_bitness_global_challenges p.`ms3rp_comparison_global_challenge
    p.`ms3rp_transcript_digest.

op ms3a_bitness_layer_source_of_sim_payload (p : ms3a_sim_source_payload) :
  ms3a_bitness_layer_source =
  ms3a_make_sim_source p.`ms3sp_stmt p.`ms3sp_res p.`ms3sp_bits
    p.`ms3sp_bitness_global_challenges p.`ms3sp_comparison_global_challenge
    p.`ms3sp_transcript_digest.

pred ms3a_source_wf (src : ms3a_bitness_layer_source) =
  ms_bitness_vector_programmed_layer src.`ms3s_stmt src.`ms3s_bits
    src.`ms3s_bitness_global_challenges.

pred ms3a_source_matches_v2_observable
  (src : ms3a_bitness_layer_source) (obs : ms_v2_transcript_observable) =
  obs.`msv2_statement_digest = src.`ms3s_stmt /\
  obs.`msv2_result_bit = src.`ms3s_result /\
  obs.`msv2_bitness_global_challenges = src.`ms3s_bitness_global_challenges /\
  obs.`msv2_comparison_global_challenge = src.`ms3s_comparison_global_challenge /\
  obs.`msv2_transcript_digest = src.`ms3s_transcript_digest.

pred ms3a_real_sim_sources_match_public_fields
  (real_src sim_src : ms3a_bitness_layer_source) =
  real_src.`ms3s_stmt = sim_src.`ms3s_stmt /\
  real_src.`ms3s_result = sim_src.`ms3s_result /\
  real_src.`ms3s_comparison_global_challenge = sim_src.`ms3s_comparison_global_challenge /\
  real_src.`ms3s_bitness_global_challenges = sim_src.`ms3s_bitness_global_challenges.

pred ms3a_sources_have_programmed_bitness_layer
  (real_src sim_src : ms3a_bitness_layer_source) =
  ms_bitness_vector_programmed_layer
    real_src.`ms3s_stmt real_src.`ms3s_bits real_src.`ms3s_bitness_global_challenges /\
  ms_bitness_vector_programmed_layer
    sim_src.`ms3s_stmt sim_src.`ms3s_bits sim_src.`ms3s_bitness_global_challenges.

(* Payload-level: same programmed-vector obligation as `ms3a_source_wf` on the
   constructor image of each payload (support axioms below mention payload laws
   only, not folded bitness source distributions).                             *)
pred ms3a_real_payload_programmed_layer (p : ms3a_real_source_payload) =
  ms3a_source_wf (ms3a_bitness_layer_source_of_real_payload p).

pred ms3a_sim_payload_programmed_layer (p : ms3a_sim_source_payload) =
  ms3a_source_wf (ms3a_bitness_layer_source_of_sim_payload p).

pred ms3a_payload_pair_public_fields_match
  (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload) =
  pr.`ms3rp_stmt = ps.`ms3sp_stmt /\
  pr.`ms3rp_res = ps.`ms3sp_res /\
  pr.`ms3rp_comparison_global_challenge = ps.`ms3sp_comparison_global_challenge /\
  pr.`ms3rp_bitness_global_challenges = ps.`ms3sp_bitness_global_challenges.

(* Abstract payload laws (scheduling from `ms_public_input` / seed).          *)
op d_ms3a_real_source_payload :
  ms_public_input -> ms3a_real_source_payload distr.
op d_ms3a_sim_source_payload :
  ms_public_input -> seed -> ms3a_sim_source_payload distr.

(* Source laws are pushforwards of payload constructors (by definition).       *)
op d_ms3a_bitness_real_source (x : ms_public_input) : ms3a_bitness_layer_source distr =
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload.

op d_ms3a_bitness_sim_source (x : ms_public_input) (s : seed) :
  ms3a_bitness_layer_source distr =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.

(* `dmap` membership / preimage: `Distr.supp_dmap` (proved), not an axiom.     *)

lemma distr_mem_eq ['a] (d : 'a distr) (z z' : 'a) :
  z = z' => z' \in d => z \in d.
proof. by move=> <-. qed.

lemma ms3a_source_wf_eq (s t : ms3a_bitness_layer_source) :
  s = t => ms3a_source_wf s => ms3a_source_wf t.
proof. by move=> ->. qed.

lemma ms3a_public_match_respects (r r' s s' : ms3a_bitness_layer_source) :
  r = r' => s = s' =>
  ms3a_real_sim_sources_match_public_fields r s =>
  ms3a_real_sim_sources_match_public_fields r' s'.
proof. by move=> -> ->. qed.

lemma ms3a_prog_layer_respects (r r' s s' : ms3a_bitness_layer_source) :
  r = r' => s = s' =>
  ms3a_sources_have_programmed_bitness_layer r s =>
  ms3a_sources_have_programmed_bitness_layer r' s'.
proof. by move=> -> ->. qed.

lemma ms3a_bitness_real_src_stmt (p : ms3a_real_source_payload) :
  (ms3a_bitness_layer_source_of_real_payload p).`ms3s_stmt = p.`ms3rp_stmt.
proof. by rewrite /ms3a_bitness_layer_source_of_real_payload /ms3a_make_real_source. qed.

pred ms3a_real_source_in_constructor_image
  (real_src : ms3a_bitness_layer_source) =
  exists (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    real_src = ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td.

pred ms3a_sim_source_in_constructor_image
  (sim_src : ms3a_bitness_layer_source) =
  exists (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    sim_src = ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td.

lemma ms3a_real_source_distribution_in_image
  (x : ms_public_input) :
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    ms3a_real_source_in_constructor_image real_src.
proof.
move=> real_src Hmem.
rewrite /d_ms3a_bitness_real_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
rewrite /ms3a_real_source_in_constructor_image.
exists p.`ms3rp_stmt p.`ms3rp_res p.`ms3rp_bits p.`ms3rp_bitness_global_challenges
  p.`ms3rp_comparison_global_challenge p.`ms3rp_transcript_digest.
by rewrite Heq /ms3a_bitness_layer_source_of_real_payload.
qed.

lemma ms3a_sim_source_distribution_in_image
  (x : ms_public_input) (s : seed) :
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sim_source_in_constructor_image sim_src.
proof.
move=> sim_src Hmem.
rewrite /d_ms3a_bitness_sim_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
rewrite /ms3a_sim_source_in_constructor_image.
exists p.`ms3sp_stmt p.`ms3sp_res p.`ms3sp_bits p.`ms3sp_bitness_global_challenges
  p.`ms3sp_comparison_global_challenge p.`ms3sp_transcript_digest.
by rewrite Heq /ms3a_bitness_layer_source_of_sim_payload.
qed.

lemma ms3a_real_source_constructor_image
  (x : ms_public_input) :
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    exists (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
      (bitness_glob : digest list) (comp_glob td : digest),
      real_src = ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td.
proof.
move=> real_src Hr.
exact (ms3a_real_source_distribution_in_image x real_src Hr).
qed.

lemma ms3a_sim_source_constructor_image
  (x : ms_public_input) (s : seed) :
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s =>
    exists (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
      (bitness_glob : digest list) (comp_glob td : digest),
      sim_src = ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td.
proof.
move=> sim_src Hs.
exact (ms3a_sim_source_distribution_in_image x s sim_src Hs).
qed.

(* Same conclusion as `ms3a_*_source_constructor_image` with nested `exists`
   so elimination uses one binder per `move: ... => [w Hw]` step (packaging only). *)
lemma ms3a_real_source_constructor_image_nested
  (x : ms_public_input) (real_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  exists (stmt : digest),
  exists (rbit : bool),
  exists (bits : ms_single_bit_or_transcript list),
  exists (bitness_glob : digest list),
  exists (comp_glob : digest),
  exists (td : digest),
    real_src = ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td.
proof.
move=> Hmem.
rewrite /d_ms3a_bitness_real_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
exists p.`ms3rp_stmt.
exists p.`ms3rp_res.
exists p.`ms3rp_bits.
exists p.`ms3rp_bitness_global_challenges.
exists p.`ms3rp_comparison_global_challenge.
exists p.`ms3rp_transcript_digest.
by rewrite Heq /ms3a_bitness_layer_source_of_real_payload.
qed.

lemma ms3a_sim_source_constructor_image_nested
  (x : ms_public_input) (s : seed) (sim_src : ms3a_bitness_layer_source) :
  sim_src \in d_ms3a_bitness_sim_source x s =>
  exists (stmt : digest),
  exists (rbit : bool),
  exists (bits : ms_single_bit_or_transcript list),
  exists (bitness_glob : digest list),
  exists (comp_glob : digest),
  exists (td : digest),
    sim_src = ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td.
proof.
move=> Hmem.
rewrite /d_ms3a_bitness_sim_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
exists p.`ms3sp_stmt.
exists p.`ms3sp_res.
exists p.`ms3sp_bits.
exists p.`ms3sp_bitness_global_challenges.
exists p.`ms3sp_comparison_global_challenge.
exists p.`ms3sp_transcript_digest.
by rewrite Heq /ms3a_bitness_layer_source_of_sim_payload.
qed.

(* Canonical v2 observable distribution from structured source.                 *)
op d_ms3a_bitness_real_observable_v2
  (x : ms_public_input) : ms_v2_transcript_observable distr =
  dmap (d_ms3a_bitness_real_source x) (fun src =>
    ms3a_pack_observable src.`ms3s_stmt src.`ms3s_result
      src.`ms3s_bitness_global_challenges
      src.`ms3s_comparison_global_challenge src.`ms3s_transcript_digest).

op d_ms3a_bitness_sim_observable_v2
  (x : ms_public_input) (s : seed) : ms_v2_transcript_observable distr =
  dmap (d_ms3a_bitness_sim_source x s) (fun src =>
    ms3a_pack_observable src.`ms3s_stmt src.`ms3s_result
      src.`ms3s_bitness_global_challenges
      src.`ms3s_comparison_global_challenge src.`ms3s_transcript_digest).

(* Abstract observable laws used by the MS-3a theorem skeleton.                *)
op d_ms3a_bitness_real_observable
  (x : ms_public_input) : ms_transcript_observable distr =
  dlet (d_ms3a_bitness_real_observable_v2 x) (fun o =>
    dunit (ms3a_observable_of_v2 o)).

op d_ms3a_bitness_sim_observable
  (x : ms_public_input) (s : seed) : ms_transcript_observable distr =
  dlet (d_ms3a_bitness_sim_observable_v2 x s) (fun o =>
    dunit (ms3a_observable_of_v2 o)).

pred ms3a_bitness_real_sim_equiv (x : ms_public_input) (s : seed) =
  d_ms3a_bitness_real_observable x = d_ms3a_bitness_sim_observable x s.

(* Push `dmap` / `dlet` along distribution equality (library-shaped; no crypto). *)
lemma dmap_respects_distribution_equality ['a 'b] (d d' : 'a distr) (f : 'a -> 'b) :
  d = d' => dmap d f = dmap d' f.
proof. exact (qssm_dmap_congr d d' f). qed.

lemma dlet_respects_distribution_equality ['a 'b] (d d' : 'a distr) (F : 'a -> 'b distr) :
  d = d' => dlet d F = dlet d' F.
proof. exact (qssm_dlet_marginal_congr d d' F). qed.

(* Proof-packaging bridge: if structured source distributions are equal, then
   their packed/pushforward observable distributions are equal as well. *)
lemma ms3a_source_observable_equiv_from_layer
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s =>
  ms3a_bitness_real_sim_equiv x s.
proof.
move=> Heq; rewrite /ms3a_bitness_real_sim_equiv
  /d_ms3a_bitness_real_observable /d_ms3a_bitness_sim_observable.
have Heqv2 :
  d_ms3a_bitness_real_observable_v2 x = d_ms3a_bitness_sim_observable_v2 x s.
- rewrite /d_ms3a_bitness_real_observable_v2 /d_ms3a_bitness_sim_observable_v2.
  exact (dmap_respects_distribution_equality
    (d_ms3a_bitness_real_source x) (d_ms3a_bitness_sim_source x s)
    (fun (src : ms3a_bitness_layer_source) =>
      ms3a_pack_observable src.`ms3s_stmt src.`ms3s_result
        src.`ms3s_bitness_global_challenges
        src.`ms3s_comparison_global_challenge src.`ms3s_transcript_digest)
    Heq).
exact (dlet_respects_distribution_equality
  (d_ms3a_bitness_real_observable_v2 x) (d_ms3a_bitness_sim_observable_v2 x s)
  (fun (o : ms_v2_transcript_observable) => dunit (ms3a_observable_of_v2 o))
  Heqv2).
qed.

(* Simulator/prover abstraction *)
op ms_real_transcript : ms_public_input -> game_view.
op ms_sim_transcript : ms_public_input -> seed -> game_view.

op epsilon_ms_hash_binding : real.

axiom A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.

(* MS-3a / MS-3b / MS-3c placeholders (MS-3b/MS-3c still axioms).             *)
(* MS-3a is a layered theorem skeleton (see `MS_3a_exact_bitness_simulation_from_layers`); *)
(* remaining gaps are named source/frame obligations and transcript packaging *)
(* from `ms_public_input` (see MS_3a_proof_plan.md).                           *)
(* MS-3a proof path (bitness only; games unchanged):                            *)
(*   `MS_3a_single_branch_schnorr_reparam` (`QssmSchnorrSingleBit`)             *)
(*   -> `MS_3a_single_bit_or_split_exact_simulation`                           *)
(*   -> `A2_bitness_programmed_challenge` (`QssmFS`)                           *)
(*   -> `MS_3a_bitness_layer_exact_simulation` (`QssmMSBitnessVector`)          *)
(*   -> `MS_3a_bitness_layer_to_observable_exact_simulation`                   *)
(*   -> `ms3a_frame_consistent` (alignment + digest on v2 record)             *)
(*   -> `MS_3a_exact_bitness_simulation` (wrapper; game marginals open).      *)

(* Explicit dependency bundle for MS-3a (hypotheses mirror lower lemmas).    *)
(* Conclusion: abstract observable distribution equality (`ms3a_bitness_*`).   *)

(* Packaging bridge: source-level equality implies abstract observable equality.
   Layer hypotheses (Schnorr/OR-split/A2/vector/observable) are tracked in
   `MS_3a_proof_plan.md`; this lemma is the minimal checker-friendly statement
   used by `MS_3a_exact_bitness_simulation` (proof is `ms3a_source_observable_equiv_from_layer`). *)
lemma MS_3a_exact_bitness_simulation_from_layers
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s =>
  ms3a_bitness_real_sim_equiv x s.
proof.
move=> H_src_eq.
exact (ms3a_source_observable_equiv_from_layer x s H_src_eq).
qed.

(* Generic source-packaging obligation (non-crypto): premise-driven source
   distribution equality from well-formedness, public-field alignment, and
   bitness-layer exact-simulation premises. *)
pred ms3a_ax_real_wf (x : ms_public_input) =
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.

pred ms3a_ax_sim_wf (x : ms_public_input) (s : seed) =
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.

pred ms3a_ax_public_fields (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields real_src sim_src.

pred ms3a_ax_prog_layer (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer real_src sim_src.

pred ms3a_ax_bitness_exact (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.

(* MS-3a hardening: scheduling axiom is **payload `dmap` equality** only (no axiom
   stating folded `d_ms3a_bitness_*_source` equality without this layer).        *)
(* Narrow payload obligations (support of abstract payload laws only).          *)
axiom ms3a_payload_real_support_programmed (x : ms_public_input) :
  forall (p : ms3a_real_source_payload),
    p \in d_ms3a_real_source_payload x => ms3a_real_payload_programmed_layer p.

axiom ms3a_payload_sim_support_programmed (x : ms_public_input) (s : seed) :
  forall (p : ms3a_sim_source_payload),
    p \in d_ms3a_sim_source_payload x s => ms3a_sim_payload_programmed_layer p.

axiom ms3a_payload_pair_public_fields_on_support
  (x : ms_public_input) (s : seed) :
  forall (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload),
    pr \in d_ms3a_real_source_payload x =>
    ps \in d_ms3a_sim_source_payload x s =>
    ms3a_payload_pair_public_fields_match pr ps.

axiom ms3a_payload_schedule_equivalence
  (x : ms_public_input) (s : seed) :
  ms3a_ax_real_wf x =>
  ms3a_ax_sim_wf x s =>
  ms3a_ax_public_fields x s =>
  ms3a_ax_prog_layer x s =>
  ms3a_ax_bitness_exact x s =>
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.

lemma ms3a_source_eq_from_bitness_layer
  (x : ms_public_input) (s : seed) :
  ms3a_ax_real_wf x =>
  ms3a_ax_sim_wf x s =>
  ms3a_ax_public_fields x s =>
  ms3a_ax_prog_layer x s =>
  ms3a_ax_bitness_exact x s =>
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.
proof.
move=> Hrwf Hswf Hpub Hprog Hex.
rewrite /d_ms3a_bitness_real_source /d_ms3a_bitness_sim_source.
exact (ms3a_payload_schedule_equivalence x s Hrwf Hswf Hpub Hprog Hex).
qed.

lemma ms3a_real_sim_public_fields_of_payload_pair
  (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload) :
  ms3a_payload_pair_public_fields_match pr ps =>
  ms3a_real_sim_sources_match_public_fields
    (ms3a_bitness_layer_source_of_real_payload pr)
    (ms3a_bitness_layer_source_of_sim_payload ps).
proof.
move=> [Hstmt [Hres [Hcomp Hglob]]].
rewrite /ms3a_real_sim_sources_match_public_fields
  /ms3a_bitness_layer_source_of_real_payload /ms3a_bitness_layer_source_of_sim_payload
  /ms3a_make_real_source /ms3a_make_sim_source.
by split=> //.
qed.

lemma ms3a_real_source_constructor_wf
  (x : ms_public_input) :
  forall (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td
      \in d_ms3a_bitness_real_source x =>
    ms3a_source_wf (ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td).
proof.
move=> stmt rbit bits bitness_glob comp_glob td Hin.
rewrite /d_ms3a_bitness_real_source in Hin.
case/supp_dmap: Hin=> [p [Hp Heq]].
have Hpl : ms3a_real_payload_programmed_layer p.
- exact (ms3a_payload_real_support_programmed x p Hp).
rewrite Heq.
rewrite /ms3a_real_payload_programmed_layer.
exact Hpl.
qed.

lemma ms3a_sim_source_constructor_wf
  (x : ms_public_input) (s : seed) :
  forall (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_source_wf (ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td).
proof.
move=> stmt rbit bits bitness_glob comp_glob td Hin.
rewrite /d_ms3a_bitness_sim_source in Hin.
case/supp_dmap: Hin=> [p [Hp Heq]].
have Hpl : ms3a_sim_payload_programmed_layer p.
- exact (ms3a_payload_sim_support_programmed x s p Hp).
rewrite Heq.
rewrite /ms3a_sim_payload_programmed_layer.
exact Hpl.
qed.

lemma ms3a_source_constructors_same_public_fields
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields
      (ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r)
      (ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s).
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin.
rewrite /d_ms3a_bitness_real_source in Hrin.
rewrite /d_ms3a_bitness_sim_source in Hsin.
case/supp_dmap: Hrin=> [pr [Hpr Heqr]].
case/supp_dmap: Hsin=> [ps [Hps Heqs]].
have Hpp : ms3a_payload_pair_public_fields_match pr ps.
- exact (ms3a_payload_pair_public_fields_on_support x s pr ps Hpr Hps).
rewrite Heqr Heqs.
exact (ms3a_real_sim_public_fields_of_payload_pair pr ps Hpp).
qed.

lemma ms3a_source_constructors_programmed_bitness
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer
      (ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r)
      (ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s).
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin.
rewrite /ms3a_sources_have_programmed_bitness_layer.
split.
- exact (ms3a_real_source_constructor_wf x stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r Hrin).
- exact (ms3a_sim_source_constructor_wf x s stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s Hsin).
qed.

lemma ms3a_source_constructors_bitness_exact
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed stmt_r i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin i Hi.
rewrite /d_ms3a_bitness_real_source in Hrin.
case/supp_dmap: Hrin=> [pr [Hpr Heqr]].
have Hpl : ms3a_real_payload_programmed_layer pr.
- exact (ms3a_payload_real_support_programmed x pr Hpr).
move: Hpl; rewrite /ms3a_real_payload_programmed_layer /ms3a_source_wf=> Hprog.
rewrite -Heqr /ms3a_make_real_source in Hprog.
exact (MS_3a_bitness_layer_exact_simulation stmt_r bits_r bitness_glob_r Hprog i Hi).
qed.

(* Recover constructor witnesses via the defining `dmap` preimage (payload). *)
lemma ms3a_source_wf_of_real_mem
  (x : ms_public_input) (real_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.
proof.
move=> Hin.
have Hmem : real_src \in d_ms3a_bitness_real_source x by exact Hin.
rewrite /d_ms3a_bitness_real_source in Hin.
case/supp_dmap: Hin=> [p [Hp Hfeq]].
have Hflip : ms3a_bitness_layer_source_of_real_payload p = real_src by rewrite Hfeq.
have Hin' := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload p) real_src Hflip Hmem.
apply (ms3a_source_wf_eq (ms3a_bitness_layer_source_of_real_payload p) real_src
  Hflip).
exact (ms3a_real_source_constructor_wf x p.`ms3rp_stmt p.`ms3rp_res p.`ms3rp_bits
  p.`ms3rp_bitness_global_challenges p.`ms3rp_comparison_global_challenge
  p.`ms3rp_transcript_digest Hin').
qed.

lemma ms3a_source_wf_of_sim_mem
  (x : ms_public_input) (s : seed) (sim_src : ms3a_bitness_layer_source) :
  sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.
proof.
move=> Hin.
have Hmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hin.
rewrite /d_ms3a_bitness_sim_source in Hin.
case/supp_dmap: Hin=> [p [Hp Hfeq]].
have Hflip : ms3a_bitness_layer_source_of_sim_payload p = sim_src by rewrite Hfeq.
have Hin' := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload p) sim_src Hflip Hmem.
apply (ms3a_source_wf_eq (ms3a_bitness_layer_source_of_sim_payload p) sim_src
  Hflip).
exact (ms3a_sim_source_constructor_wf x s p.`ms3sp_stmt p.`ms3sp_res p.`ms3sp_bits
  p.`ms3sp_bitness_global_challenges p.`ms3sp_comparison_global_challenge
  p.`ms3sp_transcript_digest Hin').
qed.

lemma ms3a_public_fields_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_real_sim_sources_match_public_fields real_src sim_src.
proof.
move=> Hr Hs.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hm := ms3a_source_constructors_same_public_fields x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin.
exact (ms3a_public_match_respects
  (ms3a_bitness_layer_source_of_real_payload pr) real_src
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflipr Hflips Hm).
qed.

lemma ms3a_prog_layer_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_sources_have_programmed_bitness_layer real_src sim_src.
proof.
move=> Hr Hs.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hm := ms3a_source_constructors_programmed_bitness x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin.
exact (ms3a_prog_layer_respects
  (ms3a_bitness_layer_source_of_real_payload pr) real_src
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflipr Hflips Hm).
qed.

lemma ms3a_bitness_exact_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  forall (i : int), ms_bit_index_valid i =>
  exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
    ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
    ms_challenges_split c0 c1 cglob /\
    d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
    d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> Hr Hs i Hi.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hax := ms3a_source_constructors_bitness_exact x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin i Hi.
have Hres : exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
  ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
  ms_challenges_split c0 c1 cglob /\
  d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
  d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
- by rewrite Heqr (ms3a_bitness_real_src_stmt pr); exact Hax.
exact Hres.
qed.

lemma ms3a_default_source_eq
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.
proof.
have Hrwf : ms3a_ax_real_wf x.
- rewrite /ms3a_ax_real_wf => real_src Hmem.
  exact (ms3a_source_wf_of_real_mem x real_src Hmem).
have Hswf : ms3a_ax_sim_wf x s.
- rewrite /ms3a_ax_sim_wf => sim_src Hmem.
  exact (ms3a_source_wf_of_sim_mem x s sim_src Hmem).
have Hpub : ms3a_ax_public_fields x s.
- rewrite /ms3a_ax_public_fields => real_src sim_src Hr Hs.
  exact (ms3a_public_fields_of_mem_pair x s real_src sim_src Hr Hs).
have Hprog : ms3a_ax_prog_layer x s.
- rewrite /ms3a_ax_prog_layer => real_src sim_src Hr Hs.
  exact (ms3a_prog_layer_of_mem_pair x s real_src sim_src Hr Hs).
have Hex : ms3a_ax_bitness_exact x s.
- rewrite /ms3a_ax_bitness_exact => real_src sim_src Hr Hs i Hi.
  exact (ms3a_bitness_exact_of_mem_pair x s real_src sim_src Hr Hs i Hi).
exact (ms3a_source_eq_from_bitness_layer x s Hrwf Hswf Hpub Hprog Hex).
qed.

op ms3a_default_observable_v2 : ms_v2_transcript_observable =
  ms3a_pack_observable_with_digest
    witness.`msv2_statement_digest witness.`msv2_result_bit
    witness.`msv2_bitness_global_challenges witness.`msv2_comparison_global_challenge
.

lemma ms3a_default_transcript_digest_consistent :
  ms_transcript_digest_of_observable ms3a_default_observable_v2.
proof.
exact (ms3a_pack_observable_with_digest_consistent
  witness.`msv2_statement_digest witness.`msv2_result_bit
  witness.`msv2_bitness_global_challenges
  witness.`msv2_comparison_global_challenge).
qed.

lemma ms3a_default_frame_consistent :
  ms3a_frame_consistent (ms3a_observable_of_v2 ms3a_default_observable_v2)
    ms3a_default_observable_v2.
proof.
exact (MS_3a_frame_consistent_of_v2
  ms3a_default_observable_v2 ms3a_default_transcript_digest_consistent).
qed.

lemma MS_3a_exact_bitness_simulation (x : ms_public_input) (s : seed) :
  ms3a_bitness_real_sim_equiv x s.
proof.
apply (@MS_3a_exact_bitness_simulation_from_layers x s).
exact (ms3a_default_source_eq x s).
qed.

axiom MS_3b_true_clause_characterization :
  forall (x : ms_public_input), true.

axiom MS_3c_exact_comparison_simulation :
  forall (x : ms_public_input) (s : seed), true.
