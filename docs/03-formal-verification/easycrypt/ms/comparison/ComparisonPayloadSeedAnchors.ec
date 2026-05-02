require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes
  ComparisonPayloadFromSeed.

(* Public-index and share-length anchors for Phase-1 from_seed; proved lemmas
   packaging schedule/transcript shape bridges. *)

(* Share-length wiring: index anchor ties ann_false to false_clause_ixs / public
   indices but does not constrain mscp_share_false; discharged by Phase-1 map
   construction (same length lists from `ms3c_public_false_clause_indices x`). *)
pred ms3c_real_from_seed_share_length_anchor
  (x : ms_public_input) (sr : ms3c_real_payload_seed) =
  size (ms3c_real_payload_from_seed x sr).`mscp_share_false =
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false.

lemma A_ms3c_real_from_seed_uses_share_length :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    ms3c_real_from_seed_share_length_anchor x sr.
proof.
move=> x sr.
rewrite /ms3c_real_from_seed_share_length_anchor /ms3c_real_payload_from_seed
  /ms3c_phase1_payload_from_public_input /=.
by rewrite !size_map.
qed.

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

lemma A_ms3c_real_from_seed_uses_public_indices :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    ms3c_real_from_seed_public_index_anchor x sr.
proof.
move=> x sr.
rewrite /ms3c_real_from_seed_public_index_anchor /ms3c_real_payload_from_seed
  /ms3c_phase1_payload_from_public_input /=.
by split=> //; rewrite size_map.
qed.

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

lemma A_ms3c_sim_from_seed_uses_share_length :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_sim_from_seed_share_length_anchor x s ss.
proof.
move=> x s ss.
rewrite /ms3c_sim_from_seed_share_length_anchor /ms3c_sim_payload_from_seed
  /ms3c_phase1_payload_from_public_input /=.
by rewrite !size_map.
qed.

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

lemma A_ms3c_sim_from_seed_uses_public_indices :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_sim_from_seed_public_index_anchor x s ss.
proof.
move=> x s ss.
rewrite /ms3c_sim_from_seed_public_index_anchor /ms3c_sim_payload_from_seed
  /ms3c_phase1_payload_from_public_input /=.
by split=> //; rewrite size_map.
qed.

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
