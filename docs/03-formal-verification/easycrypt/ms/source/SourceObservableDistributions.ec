require import AllCore List Distr.
require import QssmTypes.
require import TranscriptObservable.
require import SourceModel.
require import SourceTypes SourceConstructors BitnessOne.
require import SourceBitnessDistributions.

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
