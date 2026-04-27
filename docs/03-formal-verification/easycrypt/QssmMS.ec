require import AllCore List Distr.
require import QssmTypes QssmFS.
(* MS v2 single-bit OR bitness (two branches + challenge split); pulls in
   QssmSchnorrSingleBit transitively. *)
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
  (stmt : digest) (res : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest) : ms_v2_transcript_observable =
  {| msv2_statement_digest = stmt;
     msv2_result_bit = res;
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
  (stmt : digest) (res : bool)
  (bitness_glob : digest list)
  (comp_glob : digest)
  (td : digest)
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable) =
  o = ms3a_pack_observable stmt res bitness_glob comp_glob td /\
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
  (stmt : digest) (res : bool) (bitness_glob : digest list)
  (comp_glob : digest) (td : digest) :
  td = ms_transcript_digest_public_fields
        (ms3a_pack_observable stmt res bitness_glob comp_glob td) =>
  ms_transcript_digest_of_observable
    (ms3a_pack_observable stmt res bitness_glob comp_glob td).
proof.
by rewrite /ms_transcript_digest_of_observable.
qed.

(* Digest-by-construction constructor (generic, non-default-specific).        *)
op ms3a_pack_observable_with_digest
  (stmt : digest) (res : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) : ms_v2_transcript_observable.

axiom ms3a_pack_observable_with_digest_field_correct
  (stmt : digest) (res : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms3a_pack_observable_with_digest stmt res bitness_glob comp_glob =
  ms3a_pack_observable stmt res bitness_glob comp_glob
    (ms_transcript_digest_public_fields
      (ms3a_pack_observable_with_digest stmt res bitness_glob comp_glob)).

lemma ms3a_pack_observable_with_digest_consistent
  (stmt : digest) (res : bool)
  (bitness_glob : digest list)
  (comp_glob : digest) :
  ms_transcript_digest_of_observable
    (ms3a_pack_observable_with_digest stmt res bitness_glob comp_glob).
proof.
rewrite (ms3a_pack_observable_with_digest_field_correct
  stmt res bitness_glob comp_glob).
by rewrite /ms_transcript_digest_of_observable.
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
  (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = res;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

op ms3a_make_sim_source
  (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
  (bitness_glob : digest list) (comp_glob : digest) (td : digest) :
  ms3a_bitness_layer_source =
  {| ms3s_stmt = stmt;
     ms3s_result = res;
     ms3s_bits = bits;
     ms3s_bitness_global_challenges = bitness_glob;
     ms3s_comparison_global_challenge = comp_glob;
     ms3s_transcript_digest = td |}.

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

(* Real/sim source distributions (still abstract), but now structured.         *)
op d_ms3a_bitness_real_source :
  ms_public_input -> ms3a_bitness_layer_source distr.
op d_ms3a_bitness_sim_source :
  ms_public_input -> seed -> ms3a_bitness_layer_source distr.

pred ms3a_real_source_in_constructor_image
  (real_src : ms3a_bitness_layer_source) =
  exists (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    real_src = ms3a_make_real_source stmt res bits bitness_glob comp_glob td.

pred ms3a_sim_source_in_constructor_image
  (sim_src : ms3a_bitness_layer_source) =
  exists (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    sim_src = ms3a_make_sim_source stmt res bits bitness_glob comp_glob td.

(* Constructor-image closure obligations for abstract source distributions
   (source-packaging only; non-crypto, non-ROM). *)
axiom ms3a_real_source_distribution_in_image
  (x : ms_public_input) :
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    ms3a_real_source_in_constructor_image real_src.

axiom ms3a_sim_source_distribution_in_image
  (x : ms_public_input) (s : seed) :
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sim_source_in_constructor_image sim_src.

lemma ms3a_real_source_constructor_image
  (x : ms_public_input) :
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    exists (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
      (bitness_glob : digest list) (comp_glob td : digest),
      real_src = ms3a_make_real_source stmt res bits bitness_glob comp_glob td.
proof.
move=> real_src Hr.
exact (ms3a_real_source_distribution_in_image x real_src Hr).
qed.

lemma ms3a_sim_source_constructor_image
  (x : ms_public_input) (s : seed) :
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s =>
    exists (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
      (bitness_glob : digest list) (comp_glob td : digest),
      sim_src = ms3a_make_sim_source stmt res bits bitness_glob comp_glob td.
proof.
move=> sim_src Hs.
exact (ms3a_sim_source_distribution_in_image x s sim_src Hs).
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

(* Proof-packaging bridge: if structured source distributions are equal, then
   their packed/pushforward observable distributions are equal as well. *)
lemma ms3a_source_observable_equiv_from_layer
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s =>
  ms3a_bitness_real_sim_equiv x s.
proof.
by move=> ->.
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
lemma MS_3a_exact_bitness_simulation_from_layers
  (obs : ms_transcript_observable) (o : ms_v2_transcript_observable)
  (H_frame : ms3a_frame_consistent obs o)
  (H_schnorr : forall (w c : scalar), d_ms3a_schnorr_real w c = d_ms3a_schnorr_sim w c)
  (H_or_split : forall (w0 w1 c0 c1 cglob : scalar),
      ms_challenges_split c0 c1 cglob =>
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1)
  (H_a2_bit : forall (stmt : digest) (i : int) (d0 d1 : digest),
      exists (s : scalar), ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1) = s)
  (H_bitness_layer :
     forall (stmt : digest) (bits : ms_single_bit_or_transcript list) (globdig : digest list),
       ms_bitness_vector_programmed_layer stmt bits globdig =>
       forall (i : int), ms_bit_index_valid i =>
       exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
         ms_bitness_fs_programmed stmt i d0 d1 cglob /\
         ms_challenges_split c0 c1 cglob /\
         d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
         d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1)
  (H_bitness_obs :
     forall (stmt : digest) (res : bool)
       (bits : ms_single_bit_or_transcript list) (globdig : digest list)
       (o' : ms_v2_transcript_observable),
       ms_bitness_vector_programmed_layer stmt bits globdig =>
       ms_bitness_vector_matches_observable stmt res globdig o' =>
       ms_transcript_digest_of_observable o' =>
       forall (i : int), ms_bit_index_valid i =>
       exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
         ms_bitness_fs_programmed stmt i d0 d1 cglob /\
         ms_challenges_split c0 c1 cglob /\
         d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
         d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1)
  (x : ms_public_input) (s : seed) :
  (H_src_eq : d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s) =>
  ms3a_bitness_real_sim_equiv x s.
proof.
(* Lower MS-3a lemmas justify source-level equality; this bridge turns source
   equality into the observable distribution equality goal. *)
move=> H_src_eq.
exact (ms3a_source_observable_equiv_from_layer x s H_src_eq).
qed.

(* Generic source-packaging obligation (non-crypto): premise-driven source
   distribution equality from well-formedness, public-field alignment, and
   bitness-layer exact-simulation premises. *)
axiom ms3a_source_eq_from_bitness_layer
  (x : ms_public_input) (s : seed)
  (H_real_wf : forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src)
  (H_sim_wf : forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src)
  (H_public_fields : forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields real_src sim_src)
  (H_prog_layer : forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer real_src sim_src)
  (H_bitness_exact : forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.

axiom ms3a_real_source_constructor_wf
  (x : ms_public_input) :
  forall (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_real_source stmt res bits bitness_glob comp_glob td
      \in d_ms3a_bitness_real_source x =>
    ms3a_source_wf (ms3a_make_real_source stmt res bits bitness_glob comp_glob td).

axiom ms3a_sim_source_constructor_wf
  (x : ms_public_input) (s : seed) :
  forall (stmt : digest) (res : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_sim_source stmt res bits bitness_glob comp_glob td
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_source_wf (ms3a_make_sim_source stmt res bits bitness_glob comp_glob td).

axiom ms3a_source_constructors_same_public_fields
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

axiom ms3a_source_constructors_programmed_bitness
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

axiom ms3a_source_constructors_bitness_exact
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

lemma ms3a_default_source_eq
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.
proof.
have Hrwf : forall (real_src : ms3a_bitness_layer_source),
  real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.
- move=> real_src Hmem.
  have [stmt [res [bits [bitness_glob [comp_glob [td ->]]]]]] :=
    ms3a_real_source_constructor_image x real_src Hmem.
  exact (ms3a_real_source_constructor_wf x stmt res bits bitness_glob comp_glob td Hmem).
have Hswf : forall (sim_src : ms3a_bitness_layer_source),
  sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.
- move=> sim_src Hmem.
  have [stmt [res [bits [bitness_glob [comp_glob [td ->]]]]]] :=
    ms3a_sim_source_constructor_image x s sim_src Hmem.
  exact (ms3a_sim_source_constructor_wf x s stmt res bits bitness_glob comp_glob td Hmem).
have Hpub : forall (real_src sim_src : ms3a_bitness_layer_source),
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_real_sim_sources_match_public_fields real_src sim_src.
- move=> real_src sim_src Hr Hs.
  have [stmt_r [res_r [bits_r [bitness_glob_r [comp_glob_r [td_r ->]]]]]] :=
    ms3a_real_source_constructor_image x real_src Hr.
  have [stmt_s [res_s [bits_s [bitness_glob_s [comp_glob_s [td_s ->]]]]]] :=
    ms3a_sim_source_constructor_image x s sim_src Hs.
  exact (ms3a_source_constructors_same_public_fields x s
    stmt_r stmt_s res_r res_s bits_r bits_s
    bitness_glob_r bitness_glob_s comp_glob_r comp_glob_s td_r td_s Hr Hs).
have Hprog : forall (real_src sim_src : ms3a_bitness_layer_source),
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_sources_have_programmed_bitness_layer real_src sim_src.
- move=> real_src sim_src Hr Hs.
  have [stmt_r [res_r [bits_r [bitness_glob_r [comp_glob_r [td_r ->]]]]]] :=
    ms3a_real_source_constructor_image x real_src Hr.
  have [stmt_s [res_s [bits_s [bitness_glob_s [comp_glob_s [td_s ->]]]]]] :=
    ms3a_sim_source_constructor_image x s sim_src Hs.
  exact (ms3a_source_constructors_programmed_bitness x s
    stmt_r stmt_s res_r res_s bits_r bits_s
    bitness_glob_r bitness_glob_s comp_glob_r comp_glob_s td_r td_s Hr Hs).
have Hexact : forall (real_src sim_src : ms3a_bitness_layer_source),
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  forall (i : int), ms_bit_index_valid i =>
  exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
    ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
    ms_challenges_split c0 c1 cglob /\
    d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
    d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
- move=> real_src sim_src Hr Hs i Hi.
  have [stmt_r [res_r [bits_r [bitness_glob_r [comp_glob_r [td_r Hreq]]]]]] :=
    ms3a_real_source_constructor_image x real_src Hr.
  have [stmt_s [res_s [bits_s [bitness_glob_s [comp_glob_s [td_s Hseq]]]]]] :=
    ms3a_sim_source_constructor_image x s sim_src Hs.
  rewrite Hreq.
  exact (ms3a_source_constructors_bitness_exact x s
    stmt_r stmt_s res_r res_s bits_r bits_s
    bitness_glob_r bitness_glob_s comp_glob_r comp_glob_s td_r td_s Hr Hs i Hi).
exact (ms3a_source_eq_from_bitness_layer x s Hrwf Hswf Hpub Hprog Hexact).
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
apply (@MS_3a_exact_bitness_simulation_from_layers
  (ms3a_observable_of_v2 ms3a_default_observable_v2) ms3a_default_observable_v2 _
  (@MS_3a_single_branch_schnorr_reparam)
  (@MS_3a_single_bit_or_split_exact_simulation)
  (fun stmt i d0 d1 => @A2_bitness_programmed_challenge stmt i d0 d1)
  (@MS_3a_bitness_layer_exact_simulation)
  (@MS_3a_bitness_layer_to_observable_exact_simulation)
  x s).
exact ms3a_default_frame_consistent.
exact (ms3a_default_source_eq x s).
qed.

axiom MS_3b_true_clause_characterization :
  forall (x : ms_public_input), true.

axiom MS_3c_exact_comparison_simulation :
  forall (x : ms_public_input) (s : seed), true.
