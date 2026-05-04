require import AllCore List.
require import Domains QssmTypes FS BitnessOne BitnessVector.

(* MS v2 transcript observable (canonical record) aligned to execution-spec fields.
  The base observable carrier `ms_transcript_observable` now uses this exact
  field layout, so the v2 surface is just a stable alias used throughout the
  MS-3a source/game chain. *)

type ms_v2_transcript_observable = ms_transcript_observable.

(* Result-bit marker used when hashing the public transcript surface. *)
op ms_result_bit_digest (b : bool) : digest =
  if b then hash_domain DOMAIN_SEAM_MS_V2_BINDING []
  else hash_domain DOMAIN_SEAM_MS_V2_OPEN [].

op ms_transcript_digest_public_fields (o : ms_v2_transcript_observable) : digest =
  hash_domain LABEL_MS_V2_PROOF
    (o.`msv2_statement_digest ::
     ms_result_bit_digest o.`msv2_result_bit ::
     o.`msv2_comparison_global_challenge ::
     o.`msv2_bitness_global_challenges).

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
