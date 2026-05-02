require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayloadSeeds.
require import ComparisonPayloadSupportTypes.

(* Public-field obligation predicates and packaging lemmas. *)

pred ms3c_ax_payload_public_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_public_fields_match pr ps.

pred ms3c_ax_payload_index_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_index_fields_match pr ps.

pred ms3c_ax_payload_ann_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_ann_fields_match pr ps.

pred ms3c_ax_payload_stmt_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_stmt_fields_match pr ps.

pred ms3c_ax_payload_result_fields_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_result_fields_match pr ps.

lemma L_ms3c_ax_payload_public_fields_match_from_fragments
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_index_fields_match x s =>
  ms3c_ax_payload_ann_fields_match x s =>
  ms3c_ax_payload_stmt_fields_match x s =>
  ms3c_ax_payload_result_fields_match x s =>
  ms3c_ax_payload_public_fields_match x s.
proof.
move=> Hix Hann Hstmt Hres.
rewrite /ms3c_ax_payload_public_fields_match => pr ps Hpr Hps.
move: (Hix pr ps Hpr Hps) (Hann pr ps Hpr Hps) (Hstmt pr ps Hpr Hps) (Hres pr ps Hpr Hps).
move=> [Hi1 Hi2] [Ha1 Ha2] Hq [Hg Hp].
rewrite /ms3c_payload_pair_public_fields_match.
split; first exact Hi1.
split; first exact Hi2.
split; first exact Ha1.
split; first exact Ha2.
split; first exact Hq.
split; first exact Hg.
exact Hp.
qed.

pred ms3c_ax_payload_announcement_digests_preserved (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_clause_ann_digests_from_surface (ms3c_make_real_clause_surface pr) =
    ms3c_clause_ann_digests_from_surface (ms3c_make_sim_clause_surface ps).

pred ms3c_ax_payload_announcements_match_shape (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_payload_ann_digest_list_shape_ok pr) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_ann_digest_list_shape_ok ps).

lemma L_ms3c_ax_payload_announcements_match_shape_total
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_announcements_match_shape x s.
proof.
rewrite /ms3c_ax_payload_announcements_match_shape.
split.
  move=> pr _.
  exact (L_ms3c_real_payload_ann_digest_list_shape_ok x pr).
move=> ps _.
exact (L_ms3c_sim_payload_ann_digest_list_shape_ok x s ps).
qed.

pred ms3c_ax_payload_challenge_share_consistency (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_payload_programmed_challenge_matches_global pr) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_programmed_challenge_matches_global ps).
