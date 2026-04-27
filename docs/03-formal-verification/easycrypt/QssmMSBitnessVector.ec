require import AllCore List.
require import QssmTypes QssmFS QssmMSBitnessSingle.

(* ========================================================================== *)
(* QssmMSBitnessVector — MS v2 bitness across all bit indices (width 64).   *)
(* Lifts QssmMSBitnessSingle (one-bit OR + programmed FS). List order models *)
(* ordered bitness_global_challenges (execution spec / SimulatedMsV2).       *)
(* Comparison (MS-3c) and transcript_digest bridge stay out of scope.      *)
(* ========================================================================== *)

(* Rust / truth-engine: predicate-only MS v2 bit count. *)
op V2_BIT_COUNT : int = 64.

(* Bitness lane index (execution-spec `bit_index` as int). *)
pred ms_bit_index_valid (i : int) =
  0 <= i /\ i < V2_BIT_COUNT.

(* Abstract map from per-bit global FS scalar to digest cell in                *)
(* `ms_bitness_global_challenges` (MS transcript observable).               *)
op ms_bitness_challenge_scalar_digest : scalar -> digest.

op ms_nth_single_bit_or (bits : ms_single_bit_or_transcript list) (i : int) :
  ms_single_bit_or_transcript =
  nth witness bits i.

(* -------------------------------------------------------------------------- *)
(* Vector / list layer (length 64 each; order = challenge vector order).      *)
(* -------------------------------------------------------------------------- *)

pred ms_bitness_vector_length_ok (bits : ms_single_bit_or_transcript list) =
  size bits = V2_BIT_COUNT.

pred ms_bitness_global_challenge_vector_length_ok (globdig : digest list) =
  size globdig = V2_BIT_COUNT.

pred ms_per_bit_programmed (stmt : digest) (bits : ms_single_bit_or_transcript list) =
  forall (i : int),
    ms_bit_index_valid i =>
    let t = ms_nth_single_bit_or bits i in
    msbt_stmt t = stmt /\
    ms_single_bit_programmed_bitness_transcript stmt i t.`msbt_pub0 t.`msbt_pub1
      t.`msbt_branch0 t.`msbt_branch1
      t.`msbt_challenge_zero t.`msbt_challenge_one t.`msbt_global_challenge.

pred ms_ordered_challenge_vector_matches
  (bits : ms_single_bit_or_transcript list) (globdig : digest list) =
  ms_bitness_vector_length_ok bits /\
  ms_bitness_global_challenge_vector_length_ok globdig /\
  forall (i : int),
    ms_bit_index_valid i =>
    nth witness globdig i =
      ms_bitness_challenge_scalar_digest (ms_nth_single_bit_or bits i).`msbt_global_challenge.

(* Full programmed bitness vector layer (composition of one-bit predicates + *)
(* ordered digest vector). Length constraints are folded into `ms_ordered_*`. *)
pred ms_bitness_vector_programmed_layer
  (stmt : digest) (bits : ms_single_bit_or_transcript list) (globdig : digest list) =
  ms_per_bit_programmed stmt bits /\
  ms_ordered_challenge_vector_matches bits globdig.

(* Bridge to `ms_bitness_global_challenges` (QssmMS.ec): ordered digest list. *)
pred ms_transcript_bitness_digests_match_vector
  (obs_chals : digest list) (globdig : digest list) =
  obs_chals = globdig.

(* -------------------------------------------------------------------------- *)
(* Lift lemmas.                                                              *)
(* `MS_3a_single_bit_programmed_or_split_exact_simulation` is invoked per    *)
(* index once witness scalars and digests are read from `nth bits i` in a    *)
(* distributional packaging (still future work for `MS_3a_bitness_layer_*`).*)
(* -------------------------------------------------------------------------- *)

lemma MS_3a_ordered_challenge_vector_consistency
  (bits : ms_single_bit_or_transcript list) (globdig : digest list) :
  ms_ordered_challenge_vector_matches bits globdig <=>
  (ms_bitness_vector_length_ok bits /\
   ms_bitness_global_challenge_vector_length_ok globdig /\
   forall (i : int),
     ms_bit_index_valid i =>
     nth witness globdig i =
       ms_bitness_challenge_scalar_digest (ms_nth_single_bit_or bits i).`msbt_global_challenge).
proof.
by rewrite /ms_ordered_challenge_vector_matches.
qed.

lemma MS_3a_all_bits_from_single_bit (stmt : digest)
  (bits : ms_single_bit_or_transcript list) (globdig : digest list) :
  ms_bitness_vector_programmed_layer stmt bits globdig =>
  ms_per_bit_programmed stmt bits /\
  ms_ordered_challenge_vector_matches bits globdig.
proof.
by move=> [Hper Ho]; split=> //.
qed.

lemma MS_3a_bitness_layer_exact_simulation (stmt : digest)
  (bits : ms_single_bit_or_transcript list) (globdig : digest list) :
  ms_bitness_vector_programmed_layer stmt bits globdig =>
  forall (i : int), ms_bit_index_valid i =>
  exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
    ms_bitness_fs_programmed stmt i d0 d1 cglob /\
    ms_challenges_split c0 c1 cglob /\
    d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
    d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> [Hper _] i Hi.
pose t := ms_nth_single_bit_or bits i.
have Hti : msbt_stmt t = stmt /\
  ms_single_bit_programmed_bitness_transcript stmt i t.`msbt_pub0 t.`msbt_pub1
    t.`msbt_branch0 t.`msbt_branch1
    t.`msbt_challenge_zero t.`msbt_challenge_one t.`msbt_global_challenge
  by exact (Hper i Hi).
have [_ Hprog] := Hti.
have [_ [_ [Hsplit Hfs]]] := Hprog.
exists witness, witness,
       t.`msbt_challenge_zero, t.`msbt_challenge_one, t.`msbt_global_challenge,
       (ms_single_bit_branch_digest t.`msbt_pub0),
       (ms_single_bit_branch_digest t.`msbt_pub1).
split.
- exact Hfs.
split.
- exact Hsplit.
exact (MS_3a_single_bit_programmed_or_split_exact_simulation
  witness witness t.`msbt_challenge_zero t.`msbt_challenge_one t.`msbt_global_challenge
  stmt i (ms_single_bit_branch_digest t.`msbt_pub0) (ms_single_bit_branch_digest t.`msbt_pub1)
  Hfs Hsplit).
qed.
