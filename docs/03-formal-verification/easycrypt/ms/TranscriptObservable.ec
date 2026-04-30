require import AllCore List.
require import QssmTypes FS BitnessOne BitnessVector.

(* MS v2 transcript observable (canonical record) aligned to execution-spec fields;
   bridges bitness vector layer to digest / transcript_digest story.
   Abstract `ms_transcript_observable` accessors live in `ms/SourceModel.ec`
   (observable frame); structured MS-3a source material is under `ms/source/`;
   this file supplies the concrete v2 record and relations used on the path to
   `ms3a_bitness_real_sim_equiv` / MS-3a. *)

type ms_v2_transcript_observable = {
  msv2_statement_digest : digest;
  msv2_result_bit : bool;
  msv2_bitness_global_challenges : digest list;
  msv2_comparison_global_challenge : digest;
  msv2_transcript_digest : digest;
}.

op ms_transcript_digest_public_fields (o : ms_v2_transcript_observable) : digest.

pred ms_bitness_vector_matches_observable
  (stmt : digest) (rbit : bool) (globdig : digest list)
  (o : ms_v2_transcript_observable) =
  o.`msv2_statement_digest = stmt /\
  o.`msv2_result_bit = rbit /\
  ms_transcript_bitness_digests_match_vector o.`msv2_bitness_global_challenges globdig.

pred ms_transcript_digest_of_observable (o : ms_v2_transcript_observable) =
  o.`msv2_transcript_digest = ms_transcript_digest_public_fields o.

lemma MS_3a_observable_bitness_challenges_consistent
  (stmt : digest) (rbit : bool) (globdig : digest list)
  (o : ms_v2_transcript_observable) :
  ms_bitness_vector_matches_observable stmt rbit globdig o =>
  ms_transcript_bitness_digests_match_vector o.`msv2_bitness_global_challenges globdig.
proof.
rewrite /ms_bitness_vector_matches_observable.
by move=> [_ [_ Hmatch]].
qed.

lemma MS_3a_observable_transcript_digest_consistent
  (o : ms_v2_transcript_observable) :
  ms_transcript_digest_of_observable o <=>
  o.`msv2_transcript_digest = ms_transcript_digest_public_fields o.
proof.
by rewrite /ms_transcript_digest_of_observable.
qed.

lemma MS_3a_bitness_layer_to_observable_exact_simulation
  (stmt : digest) (rbit : bool)
  (bits : ms_single_bit_or_transcript list) (globdig : digest list)
  (o : ms_v2_transcript_observable) :
  ms_bitness_vector_programmed_layer stmt bits globdig =>
  ms_bitness_vector_matches_observable stmt rbit globdig o =>
  ms_transcript_digest_of_observable o =>
  forall (i : int), ms_bit_index_valid i =>
  exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
    ms_bitness_fs_programmed stmt i d0 d1 cglob /\
    ms_challenges_split c0 c1 cglob /\
    d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
    d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> Hp _Ho _Hd i Hi.
exact (MS_3a_bitness_layer_exact_simulation stmt bits globdig Hp i Hi).
qed.
