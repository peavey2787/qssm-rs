require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes.

(* Seed laws, shape axioms, and payload laws as `dmap` pushforwards of seeds.

   Discharge path: all four component laws d_ms3c_real_seed_challenge,
   d_ms3c_sim_seed_challenge, d_ms3c_real_seed_announcement, and
   d_ms3c_sim_seed_announcement are dunit tt on unit with proved losslessness
   lemmata (Phase-1 scaffolding; not final ROM, FS, or Schnorr announcement
   samplers). Real/sim index-shape are lemmata L_ms3c_{real,sim}_seed_index_shape_valid
   from ms3c_public_shape_ok (placeholder public ops) plus narrow axioms
   A_ms3c_{real,sim}_from_seed_uses_public_indices. Real/sim ann/share lengths are
   lemmata L_ms3c_{real,sim}_seed_length_shape_valid from narrow
   A_ms3c_{real,sim}_from_seed_uses_share_length. Remaining: from_seed wiring beyond
   anchors until constructors are concrete.

   Missing for proofs: defining equations for ms3c real and sim payload from seed
   beyond the narrow anchor axioms. *)

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

op ms3c_real_payload_from_seed (x : ms_public_input) :
  ms3c_real_payload_seed -> ms3c_real_comparison_payload.

op ms3c_sim_payload_from_seed (x : ms_public_input) (s : seed) :
  ms3c_sim_payload_seed -> ms3c_sim_comparison_payload.

(* Share-length wiring: index anchor ties ann_false to false_clause_ixs / public
   indices but does not constrain mscp_share_false; discharge via constructor or
   this narrow anchor until from_seed is concrete. *)
pred ms3c_real_from_seed_share_length_anchor
  (x : ms_public_input) (sr : ms3c_real_payload_seed) =
  size (ms3c_real_payload_from_seed x sr).`mscp_share_false =
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false.

axiom A_ms3c_real_from_seed_uses_share_length :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    ms3c_real_from_seed_share_length_anchor x sr.

lemma L_ms3c_real_seed_length_shape_valid (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  ms3c_real_from_seed_share_length_anchor x sr =>
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
  size (ms3c_real_payload_from_seed x sr).`mscp_share_false.
proof.
by move=> Hshare; rewrite -Hshare.
qed.

(* Narrow constructor obligation: real payload indices and ann/false-ix sizes
   align with ComparisonTypes.ms3c_public_* projections (discharge when from_seed
   is defined or by transcript construction). *)
pred ms3c_real_from_seed_public_index_anchor (x : ms_public_input) (sr : ms3c_real_payload_seed) =
  (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs =
    ms3c_public_false_clause_indices x /\
  (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix =
    ms3c_public_true_clause_index x /\
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.

axiom A_ms3c_real_from_seed_uses_public_indices :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    ms3c_real_from_seed_public_index_anchor x sr.

lemma L_ms3c_real_seed_index_shape_valid (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  ms3c_real_from_seed_public_index_anchor x sr =>
  0 <= (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix /\
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
  size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
move=> [Hfalse_ixs [Htrue_ix Hsz_ann_false]].
(* `ms3c_public_shape_ok x` holds for placeholder public ops; first conjunct supplies `0 <=` public true index. *)
have Hpub : ms3c_public_shape_ok x.
  rewrite /ms3c_public_shape_ok /=.
  by split=> //; split=> //.
split.
- by rewrite Htrue_ix; case: Hpub.
by exact Hsz_ann_false.
qed.

pred ms3c_sim_from_seed_share_length_anchor
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_share_false =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false.

axiom A_ms3c_sim_from_seed_uses_share_length :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_sim_from_seed_share_length_anchor x s ss.

lemma L_ms3c_sim_seed_length_shape_valid
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ms3c_sim_from_seed_share_length_anchor x s ss =>
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_share_false.
proof.
by move=> Hshare; rewrite -Hshare.
qed.

(* Narrow constructor obligation: sim payload indices and ann/false-ix sizes
   align with ComparisonTypes.ms3c_public_* projections (discharge when from_seed
   is defined or by transcript construction). *)
pred ms3c_sim_from_seed_public_index_anchor
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) =
  (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs =
    ms3c_public_false_clause_indices x /\
  (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix =
    ms3c_public_true_clause_index x /\
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.

axiom A_ms3c_sim_from_seed_uses_public_indices :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_sim_from_seed_public_index_anchor x s ss.

lemma L_ms3c_sim_seed_index_shape_valid
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ms3c_sim_from_seed_public_index_anchor x s ss =>
  0 <= (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix /\
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
move=> [Hfalse_ixs [Htrue_ix Hsz_ann_false]].
have Hpub : ms3c_public_shape_ok x.
  rewrite /ms3c_public_shape_ok /=.
  by split=> //; split=> //.
split.
- by rewrite Htrue_ix; case: Hpub.
by exact Hsz_ann_false.
qed.

op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_payload_seed x) (ms3c_real_payload_from_seed x).

op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_payload_seed x s) (ms3c_sim_payload_from_seed x s).

lemma L_ms3c_real_comparison_payload_law_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_comparison_payload x).
proof.
by rewrite /d_ms3c_real_comparison_payload; apply dmap_ll;
  apply (L_ms3c_real_payload_seed_lossless x).
qed.

lemma L_ms3c_sim_comparison_payload_law_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_comparison_payload x s).
proof.
by rewrite /d_ms3c_sim_comparison_payload; apply dmap_ll;
  apply (L_ms3c_sim_payload_seed_lossless x s).
qed.

op d_ms3c_real_comparison_schedule (x : ms_public_input) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_real_comparison_payload x) ms3c_make_real_clause_surface.

op d_ms3c_sim_comparison_schedule (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_sim_comparison_payload x s) ms3c_make_sim_clause_surface.

op d_ms3c_comparison_real_clause (x : ms_public_input) : ms_comparison_clause_surface distr =
  d_ms3c_real_comparison_schedule x.

op d_ms3c_comparison_sim_clause (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  d_ms3c_sim_comparison_schedule x s.

pred ms_comparison_exact_simulation_equiv (x : ms_public_input) (s : seed) =
  d_ms3c_comparison_real_clause x = d_ms3c_comparison_sim_clause x s.
