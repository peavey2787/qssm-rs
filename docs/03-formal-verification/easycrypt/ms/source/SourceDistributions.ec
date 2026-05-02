require import AllCore List Distr.
require import QssmTypes.
require import TranscriptObservable.
require import SourceModel.
require import SourceTypes SourceConstructors.
require import BitnessOne.

(* Payload laws as pushforwards of abstract seed distributions (MS-3a tightening). *)
op d_ms3a_real_payload_seed (x : ms_public_input) : ms3a_real_payload_seed distr.
op d_ms3a_sim_payload_seed (x : ms_public_input) (s : seed) : ms3a_sim_payload_seed distr.

op d_ms3a_real_source_payload (x : ms_public_input) : ms3a_real_source_payload distr =
  dmap (d_ms3a_real_payload_seed x) (fun sigma => ms3a_real_payload_from_seed x sigma).

op d_ms3a_sim_source_payload (x : ms_public_input) (s : seed) : ms3a_sim_source_payload distr =
  dmap (d_ms3a_sim_payload_seed x s) (fun sigma => ms3a_sim_payload_from_seed x s sigma).

(* Source laws are pushforwards of payload constructors (by definition).       *)
op d_ms3a_bitness_real_source (x : ms_public_input) : ms3a_bitness_layer_source distr =
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload.

op d_ms3a_bitness_sim_source (x : ms_public_input) (s : seed) :
  ms3a_bitness_layer_source distr =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.

(* Bitness-layer sources factor through abstract seed laws (`Distr.dmap_comp`). *)
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
