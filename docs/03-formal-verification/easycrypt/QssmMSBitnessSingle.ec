require import AllCore Distr.
require import QssmTypes.
require import QssmSchnorrSingleBit.
require import QssmFS.

(* ========================================================================== *)
(* QssmMSBitnessSingle — one MS v2 bitness index, OR-proof (two branches +   *)
(* global challenge split). Imports QssmSchnorrSingleBit + QssmFS (digest FS). *)
(* Global MS_3a axiom stays in QssmMS.ec.                                      *)
(* ========================================================================== *)

(* -------------------------------------------------------------------------- *)
(* OR-proof transcript for a single bit index: two branch observables,        *)
(* per-branch FS challenges, global challenge, public/statement material.     *)
(*                                                                            *)
(* Challenge split (Rust-style bookkeeping):                                  *)
(*   sch_s_add challenge_zero challenge_one = global_challenge                *)
(* i.e. c0 + c1 = c_glob in the abstract scalar group.                        *)
(*                                                                            *)
(* Branch observables reuse `schnorr_single_bit_obsv` = (announcement, z).   *)
(* -------------------------------------------------------------------------- *)

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

(* -------------------------------------------------------------------------- *)
(* Joint distributions on (branch0, branch1) observables only.                *)
(* Witness scalars w0, w1 match pub0, pub1 via Schnorr layer (abstract).      *)
(* Per-branch FS challenges are c0, c1; they must satisfy ms_challenges_split *)
(* with programmed global_challenge for real/sim equivalences below.         *)
(*                                                                            *)
(* Real (true bit = 0): branch 0 genuine `d_ms3a_schnorr_real`, branch 1 sim.  *)
(* Real (true bit = 1): branch 0 sim, branch 1 genuine.                       *)
(* Sim: both branches `d_ms3a_schnorr_sim` under the same split.             *)
(* -------------------------------------------------------------------------- *)

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
op d_ms_bit_or_pack stmt P0 P1 w0 w1 c0 c1 cglob
  (d_pair : (schnorr_single_bit_obsv * schnorr_single_bit_obsv) distr) :
  ms_single_bit_or_transcript distr =
  dmap d_pair (fun p =>
    ms_pack_single_bit_or stmt P0 P1 p.`1 p.`2 c0 c1 cglob).

(* -------------------------------------------------------------------------- *)
(* Distribution helpers (proved; standard Distr lemmas, not crypto).         *)
(* -------------------------------------------------------------------------- *)

lemma qssm_dlet_marginal_congr ['a 'b] (d d' : 'a distr) (F : 'a -> 'b distr) :
  d = d' => dlet d F = dlet d' F.
proof. by move=> ->. qed.

lemma qssm_dmap_congr ['a 'b] (d d' : 'a distr) (f : 'a -> 'b) :
  d = d' => dmap d f = dmap d' f.
proof. by move=> ->. qed.

(* -------------------------------------------------------------------------- *)
(* OR-split lemmas: genuine branch via `MS_3a_single_branch_schnorr_reparam`, *)
(* sim branch already `d_ms3a_schnorr_sim`; outer `dlet` congruence via      *)
(* `eq_dlet` / `in_eq_dlet` (Distr). `ms_challenges_split` is kept as a      *)
(* side-condition for future ROM / global-challenge wiring (unused here).     *)
(* -------------------------------------------------------------------------- *)

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

(* -------------------------------------------------------------------------- *)
(* Fiat–Shamir / programmed global challenge (one bit, digest-level).       *)
(* -------------------------------------------------------------------------- *)

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
have _ := A2_bitness_programmed_challenge stmt i d0 d1.
exact (MS_3a_single_bit_or_split_exact_simulation w0 w1 c0 c1 cglob Hsplit).
qed.
