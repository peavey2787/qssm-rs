require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes.

(* Phase-1 seed component laws (d_ms3c real/sim seed_challenge and
   seed_announcement) and joint seed distributions.
   Losslessness is proved from dunit_ll on unit carriers; see module comment in
   ComparisonPayloadSeeds.ec (facade) for the full discharge narrative. *)

(* Trivial real challenge-side law: placeholder until FS/challenge material is
   modeled in `ms3c_real_seed_challenge`; lossless by `dunit_ll`. *)
op d_ms3c_real_seed_challenge (_x : ms_public_input) : ms3c_real_seed_challenge distr =
  dunit tt.

(* Phase-1 scaffolding: ignores x; not the final real announcement sampler. *)
op d_ms3c_real_seed_announcement (_x : ms_public_input) : ms3c_real_seed_announcement distr =
  dunit tt.

(* Phase-1 scaffolding: not the final semantic sim ROM or FS challenge sampler. *)
op d_ms3c_sim_seed_challenge (_x : ms_public_input) (_s : seed) : ms3c_sim_seed_challenge distr =
  dunit tt.

(* Phase-1 scaffolding: ignores x and s; not the final sim announcement sampler. *)
op d_ms3c_sim_seed_announcement (_x : ms_public_input) (_s : seed) : ms3c_sim_seed_announcement distr =
  dunit tt.

op d_ms3c_real_payload_seed (x : ms_public_input) : ms3c_real_payload_seed distr =
  d_ms3c_real_seed_challenge x `*` d_ms3c_real_seed_announcement x.

op d_ms3c_sim_payload_seed (x : ms_public_input) (s : seed) : ms3c_sim_payload_seed distr =
  d_ms3c_sim_seed_challenge x s `*` d_ms3c_sim_seed_announcement x s.

lemma L_ms3c_real_seed_challenge_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_seed_challenge x).
proof.
by rewrite /d_ms3c_real_seed_challenge; apply dunit_ll.
qed.

lemma L_ms3c_sim_seed_challenge_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_seed_challenge x s).
proof.
by rewrite /d_ms3c_sim_seed_challenge; apply dunit_ll.
qed.

lemma L_ms3c_real_seed_announcement_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_seed_announcement x).
proof.
by rewrite /d_ms3c_real_seed_announcement; apply dunit_ll.
qed.

lemma L_ms3c_sim_seed_announcement_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_seed_announcement x s).
proof.
by rewrite /d_ms3c_sim_seed_announcement; apply dunit_ll.
qed.

lemma L_ms3c_real_payload_seed_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_payload_seed x).
proof.
by rewrite /d_ms3c_real_payload_seed; apply dprod_ll_auto;
  [apply (L_ms3c_real_seed_challenge_lossless x) |
   apply (L_ms3c_real_seed_announcement_lossless x)].
qed.

lemma L_ms3c_sim_payload_seed_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_payload_seed x s).
proof.
by rewrite /d_ms3c_sim_payload_seed; apply dprod_ll_auto;
  [apply (L_ms3c_sim_seed_challenge_lossless x s) |
   apply (L_ms3c_sim_seed_announcement_lossless x s)].
qed.
