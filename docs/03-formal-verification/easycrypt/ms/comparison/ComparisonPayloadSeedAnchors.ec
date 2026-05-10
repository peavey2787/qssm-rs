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
    sr \in d_ms3c_real_payload_seed x =>
    ms3c_real_from_seed_share_length_anchor x sr.
proof.
move=> x sr Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [Hsc Hsa].
have [_ [_ [_ [_ [Hshare_false _]]]]] :=
  L_ms3c_real_seed_challenge_on_support_public_surface x sc Hsc.
have [_ Hann_false] :=
  L_ms3c_real_seed_announcement_on_support_public_surface x sa Hsa.
rewrite /ms3c_real_from_seed_share_length_anchor /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components /= Hshare_false Hann_false.
rewrite /ms3c_public_false_shares /ms_public_comparison_false_shares.
rewrite /ms3c_public_false_announcements /ms3c_public_false_openings.
rewrite /ms_public_comparison_false_openings /ms_public_comparison_false_entries.
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
    sr \in d_ms3c_real_payload_seed x =>
    ms3c_real_from_seed_public_index_anchor x sr.
proof.
move=> x sr Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
case: sr Hsr => sc sa /=.
move=> [Hsc Hsa].
have [_ [Htrue_ix [Hfalse_ixs _]]] :=
  L_ms3c_real_seed_challenge_on_support_public_surface x sc Hsc.
have [_ Hann_false] :=
  L_ms3c_real_seed_announcement_on_support_public_surface x sa Hsa.
rewrite /ms3c_real_from_seed_public_index_anchor /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components /=.
split.
- exact Hfalse_ixs.
split.
- exact Htrue_ix.
have Hannsz : size (ms3c_public_false_announcements x) =
  size (ms_public_comparison_false_entries x).
  rewrite /ms3c_public_false_announcements /ms3c_public_false_openings.
  rewrite /ms_public_comparison_false_openings /ms_public_comparison_false_entries.
  by rewrite !size_map.
have Hixsz : size (ms3c_public_false_clause_indices x) =
  size (ms_public_comparison_false_entries x).
  rewrite /ms3c_public_false_clause_indices /ms_public_comparison_false_indices.
  rewrite /ms_public_comparison_false_entries.
  by rewrite size_map.
by rewrite Hann_false Hfalse_ixs Hannsz Hixsz.
qed.

lemma L_ms3c_real_seed_index_shape_valid (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  sr \in d_ms3c_real_payload_seed x =>
  0 <= (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix /\
  size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
  size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
move=> Hsr.
have [Hfalse_ixs [Htrue_ix Hsz_ann_false]] :=
  A_ms3c_real_from_seed_uses_public_indices x sr Hsr.
split.
- have [Hix _] := L_ms3c_public_shape_ok_of_native_slice x.
  have -> : (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix =
      ms3c_public_true_clause_index x by exact Htrue_ix.
  exact Hix.
by exact Hsz_ann_false.
qed.

pred ms3c_sim_from_seed_share_length_anchor
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_share_false =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false.

lemma A_ms3c_sim_from_seed_uses_share_length :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ss \in d_ms3c_sim_payload_seed x s =>
    ms3c_sim_from_seed_share_length_anchor x s ss.
proof.
move=> x s ss Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [Hsc Hsa].
have [_ [_ [_ [_ [Hshare_false _]]]]] :=
  L_ms3c_sim_seed_challenge_on_support_public_surface x s sc Hsc.
have [_ Hann_false] :=
  L_ms3c_sim_seed_announcement_on_support_public_surface x s sa Hsa.
rewrite /ms3c_sim_from_seed_share_length_anchor /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components /= Hshare_false Hann_false.
rewrite /ms3c_public_false_shares /ms_public_comparison_false_shares.
rewrite /ms3c_public_false_announcements /ms3c_public_false_openings.
rewrite /ms_public_comparison_false_openings /ms_public_comparison_false_entries.
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
    ss \in d_ms3c_sim_payload_seed x s =>
    ms3c_sim_from_seed_public_index_anchor x s ss.
proof.
move=> x s ss Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
case: ss Hss => sc sa /=.
move=> [Hsc Hsa].
have [_ [Htrue_ix [Hfalse_ixs _]]] :=
  L_ms3c_sim_seed_challenge_on_support_public_surface x s sc Hsc.
have [_ Hann_false] :=
  L_ms3c_sim_seed_announcement_on_support_public_surface x s sa Hsa.
rewrite /ms3c_sim_from_seed_public_index_anchor /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components /=.
split.
- exact Hfalse_ixs.
split.
- exact Htrue_ix.
have Hannsz : size (ms3c_public_false_announcements x) =
  size (ms_public_comparison_false_entries x).
  rewrite /ms3c_public_false_announcements /ms3c_public_false_openings.
  rewrite /ms_public_comparison_false_openings /ms_public_comparison_false_entries.
  by rewrite !size_map.
have Hixsz : size (ms3c_public_false_clause_indices x) =
  size (ms_public_comparison_false_entries x).
  rewrite /ms3c_public_false_clause_indices /ms_public_comparison_false_indices.
  rewrite /ms_public_comparison_false_entries.
  by rewrite size_map.
by rewrite Hann_false Hfalse_ixs Hannsz Hixsz.
qed.

lemma L_ms3c_sim_seed_index_shape_valid
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ss \in d_ms3c_sim_payload_seed x s =>
  0 <= (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix /\
  size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
  size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
move=> Hss.
have [Hfalse_ixs [Htrue_ix Hsz_ann_false]] :=
  A_ms3c_sim_from_seed_uses_public_indices x s ss Hss.
split.
- have [Hix _] := L_ms3c_public_shape_ok_of_native_slice x.
  have -> : (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix =
      ms3c_public_true_clause_index x by exact Htrue_ix.
  exact Hix.
by exact Hsz_ann_false.
qed.
