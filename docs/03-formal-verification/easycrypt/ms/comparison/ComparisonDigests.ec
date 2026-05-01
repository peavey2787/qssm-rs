require import AllCore List Distr.
require import Domains Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
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

lemma L_ms3c_comparison_query_digest_ann_only_any (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s.
proof.
move=> c _.
exact (L_ms3c_ann_digest_list_shape c).
qed.

(* Definitional: ordered announcement digest material is exactly the branch digests
   built from `mscc_ann_true` / `mscc_ann_false` (projection correctness). *)
lemma L_ms3c_ann_digest_projection_correct (c : ms_comparison_clause_surface) :
  ms3c_clause_ann_digests_from_surface c =
  ms3c_digest_true_announcement c.`mscc_ann_true ::
  ms3c_digest_false_announcements c.`mscc_ann_false.
proof.
by rewrite /ms3c_clause_ann_digests_from_surface.
qed.

lemma L_ms3c_ann_digests_alias (c : ms_comparison_clause_surface) :
  ms3c_clause_ann_digests c = ms3c_clause_ann_digests_from_surface c.
proof.
by rewrite /ms3c_clause_ann_digests.
qed.

(* Programmed query digest matches the ROM comparison hash on
   `stmt :: ms3c_clause_ann_digests_from_surface c` (announcement-only list). *)
axiom A_ms3c_query_digest_statement_bound :
  forall (stmt : digest) (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).

(* Ordered announcement digest list used in the comparison query (true branch
   digest first, then false-branch digests). *)
lemma L_ms3c_query_digest_ordered_announcements_bound (c : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable c =>
  ms3c_clause_ann_digests_from_surface c =
  ms3c_digest_true_announcement c.`mscc_ann_true ::
  ms3c_digest_false_announcements c.`mscc_ann_false.
proof.
move=> _.
exact (L_ms3c_ann_digest_projection_correct c).
qed.

lemma L_ms3c_query_digest_statement_bound_hash (stmt : digest) (c : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest =
  hash_domain LABEL_MS_V2_COMPARISON_QUERY (stmt :: ms3c_clause_ann_digests_from_surface c).
proof.
move=> Hsim.
by rewrite (A_ms3c_query_digest_statement_bound stmt c Hsim) /ms_comparison_query_digest.
qed.

(* Same announcement fields ⇒ same programmed query digest (witness fields irrelevant). *)
lemma L_ms3c_query_digest_no_witness_fields (stmt : digest) (c1 c2 : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable c1 =>
  ms_comparison_clause_simulatable c2 =>
  c1.`mscc_ann_true = c2.`mscc_ann_true =>
  c1.`mscc_ann_false = c2.`mscc_ann_false =>
  c1.`mscc_query_digest = c2.`mscc_query_digest.
proof.
move=> Hs1 Hs2 Hann_t Hann_f.
have Hl :
    ms3c_clause_ann_digests_from_surface c1 = ms3c_clause_ann_digests_from_surface c2.
  rewrite /ms3c_clause_ann_digests_from_surface Hann_t Hann_f.
  by [].
rewrite (A_ms3c_query_digest_statement_bound stmt c1 Hs1)
        (A_ms3c_query_digest_statement_bound stmt c2 Hs2).
rewrite Hl.
by [].
qed.

lemma L_ms3c_query_digest_uses_ann_digest_projection (stmt : digest) (c : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).
proof.
by move=> Hsim; apply (A_ms3c_query_digest_statement_bound stmt c Hsim).
qed.

(* Same announcement fields ⇒ same announcement digest list ⇒ same programmed query
   digest (alias of `L_ms3c_query_digest_no_witness_fields` with `stmt` chosen). *)
lemma L_ms3c_query_digest_excludes_witness_fields (c1 c2 : ms_comparison_clause_surface) :
  ms_comparison_clause_simulatable c1 =>
  ms_comparison_clause_simulatable c2 =>
  c1.`mscc_ann_true = c2.`mscc_ann_true =>
  c1.`mscc_ann_false = c2.`mscc_ann_false =>
  c1.`mscc_query_digest = c2.`mscc_query_digest.
proof.
move=> Hs1 Hs2 Hann_t Hann_f.
pose stmt := ms3c_comparison_stmt_digest witness.
exact (L_ms3c_query_digest_no_witness_fields stmt c1 c2 Hs1 Hs2 Hann_t Hann_f).
qed.

(* Packaging: the legacy `Hann` hook is redundant with `L_ms3c_ann_digest_list_shape`,
   but kept in the statement so callers (games / obligations) stay stable. *)
lemma L_ms3c_digest_announcement_only (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  forall (stmt : digest) (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c).
proof.
move=> _ stmt c Hsim.
exact (A_ms3c_query_digest_statement_bound stmt c Hsim).
qed.
