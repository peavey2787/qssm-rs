require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes.

(* Phase-1 seed component laws (d_ms3c real/sim seed_challenge and
   seed_announcement) and joint seed distributions.
   Losslessness is still proved from dunit_ll, but the sampled points are now
   structured transcript/ROM seed records rather than unit placeholders; see module comment in
   ComparisonPayloadSeeds.ec (facade) for the full discharge narrative. *)

(* Phase-1 real challenge-side law: deterministic transcript/ROM material from
   the native public comparison slice/openings. *)
op d_ms3c_real_seed_challenge (x : ms_public_input) : ms3c_real_seed_challenge distr =
  dunit (ms3c_phase1_seed_challenge_from_public_input x).

(* Phase-1 real announcement-side law: deterministic native announcements. *)
op d_ms3c_real_seed_announcement (x : ms_public_input) : ms3c_real_seed_announcement distr =
  dunit (ms3c_phase1_seed_announcement_from_public_input x).

(* Phase-1 sim challenge-side law: same deterministic transcript/ROM material.
   The sim seed argument remains for API stability until richer simulator coins land. *)
op d_ms3c_sim_seed_challenge (x : ms_public_input) (_s : seed) : ms3c_sim_seed_challenge distr =
  dunit (ms3c_phase1_seed_challenge_from_public_input x).

(* Phase-1 sim announcement-side law: same deterministic native announcements.
   The sim seed argument remains for API stability until richer simulator coins land. *)
op d_ms3c_sim_seed_announcement (x : ms_public_input) (_s : seed) : ms3c_sim_seed_announcement distr =
  dunit (ms3c_phase1_seed_announcement_from_public_input x).

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
