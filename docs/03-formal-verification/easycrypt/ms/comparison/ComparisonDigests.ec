require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes.

(* Ordered announcement digest material (true branch first, then false branches). *)
op ms3c_digest_true_announcement (a : sch_point) : digest =
  ms_single_bit_branch_digest a.

op ms3c_digest_false_announcements (anns : sch_point list) : digest list =
  map ms_single_bit_branch_digest anns.

op ms3c_clause_ann_digests_from_surface (c : ms_comparison_clause_surface) : digest list =
  ms3c_digest_true_announcement c.`mscc_ann_true :: ms3c_digest_false_announcements c.`mscc_ann_false.

op ms3c_clause_ann_digests (c : ms_comparison_clause_surface) : digest list =
  ms3c_clause_ann_digests_from_surface c.

pred ms3c_ann_digest_list_shape (c : ms_comparison_clause_surface) =
  size (ms3c_clause_ann_digests c) = 1 + size c.`mscc_ann_false.

pred ms3c_comparison_query_digest_ann_only (x : ms_public_input) (s : seed) =
  forall (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    ms3c_ann_digest_list_shape c.

pred ms_comparison_programmed_fs_consistent (stmt : digest) (c : ms_comparison_clause_surface) =
  c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).

lemma L_ms3c_ann_digest_list_shape (c : ms_comparison_clause_surface) :
  ms3c_ann_digest_list_shape c.
proof.
rewrite /ms3c_ann_digest_list_shape /ms3c_clause_ann_digests /ms3c_clause_ann_digests_from_surface
  /ms3c_digest_false_announcements /=.
by rewrite size_map.
qed.

(* Comparison programmed query digest uses only the ordered announcement digest projection
   (no separate abstract digest list parameter). *)
axiom A_ms3c_digest_announcement_only :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    forall (stmt : digest) (c : ms_comparison_clause_surface),
      ms_comparison_clause_simulatable c =>
      c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).
