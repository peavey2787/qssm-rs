require import AllCore Distr.
require import Algebra QssmTypes SchnorrBranch FS.

(* One MS v2 bitness index, OR-proof (two branches + global challenge split). *)

type ms_single_bit_or_transcript = {
  msbt_stmt : digest;
  msbt_pub0 : sch_point;
  msbt_pub1 : sch_point;
  msbt_branch0 : schnorr_single_bit_obsv;
  msbt_branch1 : schnorr_single_bit_obsv;
  msbt_challenge_zero : scalar;
  msbt_challenge_one : scalar;
  msbt_global_challenge : scalar;
}.

(* Challenge split predicate (record or scalar triple). *)
pred ms_challenges_split (c0 c1 cglob : scalar) =
  sch_s_add c0 c1 = cglob.

(* Abstract digest for each OR-lane announcement (maps to execution-spec
   `announce_zero` / `announce_one` preimage bytes at section F). *)
op ms_single_bit_branch_digest : sch_point -> digest.

(* One-bit programmed bitness transcript: statement, index, lane announcements,
   branch observables, per-branch FS scalars, global cglob, split, and FS tie
   of cglob to ms_bitness_query_digest / ms_query_to_scalar at those digests. *)
pred ms_single_bit_programmed_bitness_transcript (stmt : digest) (i : int)
  (P0 P1 : sch_point) (o0 o1 : schnorr_single_bit_obsv)
  (c0 c1 cglob : scalar) =
  (o0.`1 = P0) /\ (o1.`1 = P1) /\
  ms_challenges_split c0 c1 cglob /\
  ms_bitness_fs_programmed stmt i (ms_single_bit_branch_digest P0)
    (ms_single_bit_branch_digest P1) cglob.

(* Pack a full single-bit OR transcript (deterministic given fields). *)
op ms_pack_single_bit_or (stmt : digest) (P0 P1 : sch_point)
  (o0 o1 : schnorr_single_bit_obsv)
  (c0 c1 cglob : scalar) : ms_single_bit_or_transcript =
  {| msbt_stmt = stmt;
     msbt_pub0 = P0;
     msbt_pub1 = P1;
     msbt_branch0 = o0;
     msbt_branch1 = o1;
     msbt_challenge_zero = c0;
     msbt_challenge_one = c1;
     msbt_global_challenge = cglob; |}.

op d_ms_bit_or_real_bitfalse (w0 w1 c0 c1 : scalar) :
  (schnorr_single_bit_obsv * schnorr_single_bit_obsv) distr =
  dlet (d_ms3a_schnorr_real w0 c0) (fun o0 =>
  dlet (d_ms3a_schnorr_sim w1 c1) (fun o1 =>
    dunit (o0, o1))).

op d_ms_bit_or_real_bittrue (w0 w1 c0 c1 : scalar) :
  (schnorr_single_bit_obsv * schnorr_single_bit_obsv) distr =
  dlet (d_ms3a_schnorr_sim w0 c0) (fun o0 =>
  dlet (d_ms3a_schnorr_real w1 c1) (fun o1 =>
    dunit (o0, o1))).

op d_ms_bit_or_sim_both (w0 w1 c0 c1 : scalar) :
  (schnorr_single_bit_obsv * schnorr_single_bit_obsv) distr =
  dlet (d_ms3a_schnorr_sim w0 c0) (fun o0 =>
  dlet (d_ms3a_schnorr_sim w1 c1) (fun o1 =>
    dunit (o0, o1))).

(* Full transcript pushforward (point mass on stmt/pub/challenges). *)
op d_ms_bit_or_pack (stmt : digest) (P0 P1 : sch_point) (w0 w1 c0 c1 cglob : scalar)
  (d_pair : (schnorr_single_bit_obsv * schnorr_single_bit_obsv) distr) :
  ms_single_bit_or_transcript distr =
  dmap d_pair (fun (p : schnorr_single_bit_obsv * schnorr_single_bit_obsv) =>
    ms_pack_single_bit_or stmt P0 P1 (fst p) (snd p) c0 c1 cglob).

lemma qssm_dlet_marginal_congr ['a 'b] (d d' : 'a distr) (F : 'a -> 'b distr) :
  d = d' => dlet d F = dlet d' F.
proof. by move=> ->. qed.

lemma qssm_dmap_congr ['a 'b] (d d' : 'a distr) (f : 'a -> 'b) :
  d = d' => dmap d f = dmap d' f.
proof. by move=> ->. qed.

lemma MS_3a_single_bit_or_split_bit_zero (w0 w1 c0 c1 cglob : scalar) :
  ms_challenges_split c0 c1 cglob =>
  d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> _; rewrite /d_ms_bit_or_real_bitfalse /d_ms_bit_or_sim_both.
apply eq_dlet.
- by rewrite (MS_3a_single_branch_schnorr_reparam w0 c0).
by [].
qed.

lemma MS_3a_single_bit_or_split_bit_one (w0 w1 c0 c1 cglob : scalar) :
  ms_challenges_split c0 c1 cglob =>
  d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> _; rewrite /d_ms_bit_or_real_bittrue /d_ms_bit_or_sim_both.
apply in_eq_dlet=> o0 _.
apply eq_dlet.
- by rewrite (MS_3a_single_branch_schnorr_reparam w1 c1).
by [].
qed.

lemma MS_3a_single_bit_or_split_exact_simulation (w0 w1 c0 c1 cglob : scalar) :
  ms_challenges_split c0 c1 cglob =>
  d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
  d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> h; split.
- exact (MS_3a_single_bit_or_split_bit_zero w0 w1 c0 c1 cglob h).
by exact (MS_3a_single_bit_or_split_bit_one w0 w1 c0 c1 cglob h).
qed.

lemma MS_3a_single_bit_bitness_fs_consistent (stmt : digest) (i : int)
  (d0 d1 : digest) (cglob : scalar) :
  ms_bitness_fs_programmed stmt i d0 d1 cglob <=>
  cglob = ms_bitness_fs_scalar stmt i d0 d1.
proof.
split; first by rewrite /ms_bitness_fs_programmed.
by move=> ->; rewrite /ms_bitness_fs_programmed.
qed.

lemma MS_3a_single_bit_programmed_or_split_exact_simulation (w0 w1 c0 c1 cglob : scalar)
  (stmt : digest) (i : int) (d0 d1 : digest) :
  ms_bitness_fs_programmed stmt i d0 d1 cglob =>
  ms_challenges_split c0 c1 cglob =>
  d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
  d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> _Hfs Hsplit.
exact (MS_3a_single_bit_or_split_exact_simulation w0 w1 c0 c1 cglob Hsplit).
qed.
