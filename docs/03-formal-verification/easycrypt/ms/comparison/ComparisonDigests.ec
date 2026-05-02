require import AllCore List Distr.
require import Domains Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadSeeds.

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

(* Phase-1 payloads set `mscp_query_digest` from `ms3c_public_stmt_digest x`
   (canonical statement material on `ms_public_input`) and the announcement digest
   list derived from the same placeholder announcements as `ms3c_phase1_ann_digest_list`. *)

lemma A_ms3c_clause_surface_query_digest_constructed
  (x : ms_public_input) (p : ms3c_comparison_clause_payload) :
  p = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable (ms3c_make_clause_surface p) =>
  p.`mscp_query_digest =
    ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_clause_ann_digests_from_surface (ms3c_make_clause_surface p)).
proof.
move=> Hp _Hsimp.
rewrite Hp /= /ms3c_phase1_payload_from_public_input /=.
by [].
qed.

(* Surfaces whose payload is Phase-1 for this `x` inherit the ROM query digest law
   with canonical statement `ms3c_public_stmt_digest x`. *)
lemma A_ms3c_surface_query_digest_field_correct (x : ms_public_input) (c : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest =
    ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_clause_ann_digests_from_surface c).
proof.
move=> Hpayload Hsim.
pose p := ms3c_clause_surface_to_payload c.
have Heq : ms3c_make_clause_surface p = c by exact (L_ms3c_make_clause_surface_clause_surface_to_payload c).
have Hsimp' : ms_comparison_clause_simulatable (ms3c_make_clause_surface p).
  by rewrite Heq.
have Hd : p.`mscp_query_digest =
    ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_clause_ann_digests_from_surface (ms3c_make_clause_surface p)).
  apply (A_ms3c_clause_surface_query_digest_constructed x p _ Hsimp').
  by rewrite -Hpayload.
have Hann :
    ms3c_clause_ann_digests_from_surface (ms3c_make_clause_surface p) =
    ms3c_clause_ann_digests_from_surface c
  by rewrite Heq.
have Hfield : c.`mscc_query_digest = p.`mscp_query_digest.
  by rewrite -Heq /ms3c_make_clause_surface /=.
rewrite Hfield Hd.
by rewrite -Hann.
qed.

lemma A_ms3c_query_digest_statement_bound (x : ms_public_input) (c : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest =
    ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_clause_ann_digests_from_surface c).
proof.
by move=> Hpayload Hsim; apply (A_ms3c_surface_query_digest_field_correct x c Hpayload Hsim).
qed.

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

lemma L_ms3c_query_digest_statement_bound_hash (x : ms_public_input) (c : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest =
  hash_domain LABEL_MS_V2_COMPARISON_QUERY
    (ms3c_public_stmt_digest x :: ms3c_clause_ann_digests_from_surface c).
proof.
move=> Hpayload Hsim.
by rewrite (A_ms3c_query_digest_statement_bound x c Hpayload Hsim) /ms_comparison_query_digest.
qed.

(* Same announcement fields ⇒ same programmed query digest for two Phase-1-backed
   surfaces sharing the same public input `x`. *)
lemma L_ms3c_query_digest_no_witness_fields (x : ms_public_input) (c1 c2 : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c1 = ms3c_phase1_payload_from_public_input x =>
  ms3c_clause_surface_to_payload c2 = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c1 =>
  ms_comparison_clause_simulatable c2 =>
  c1.`mscc_ann_true = c2.`mscc_ann_true =>
  c1.`mscc_ann_false = c2.`mscc_ann_false =>
  c1.`mscc_query_digest = c2.`mscc_query_digest.
proof.
move=> Hp1 Hp2 Hs1 Hs2 Hann_t Hann_f.
have Hl :
    ms3c_clause_ann_digests_from_surface c1 = ms3c_clause_ann_digests_from_surface c2.
  rewrite /ms3c_clause_ann_digests_from_surface Hann_t Hann_f.
  by [].
rewrite (A_ms3c_query_digest_statement_bound x c1 Hp1 Hs1)
        (A_ms3c_query_digest_statement_bound x c2 Hp2 Hs2).
rewrite Hl.
by [].
qed.

lemma L_ms3c_query_digest_uses_ann_digest_projection (x : ms_public_input) (c : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c =>
  c.`mscc_query_digest =
    ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_clause_ann_digests_from_surface c).
proof.
by move=> Hpayload Hsim; apply (A_ms3c_query_digest_statement_bound x c Hpayload Hsim).
qed.

(* Same announcement fields ⇒ same announcement digest list ⇒ same programmed query
   digest (Phase-1 / same `x` hypothesis). *)
lemma L_ms3c_query_digest_excludes_witness_fields (x : ms_public_input) (c1 c2 : ms_comparison_clause_surface) :
  ms3c_clause_surface_to_payload c1 = ms3c_phase1_payload_from_public_input x =>
  ms3c_clause_surface_to_payload c2 = ms3c_phase1_payload_from_public_input x =>
  ms_comparison_clause_simulatable c1 =>
  ms_comparison_clause_simulatable c2 =>
  c1.`mscc_ann_true = c2.`mscc_ann_true =>
  c1.`mscc_ann_false = c2.`mscc_ann_false =>
  c1.`mscc_query_digest = c2.`mscc_query_digest.
proof.
move=> Hp1 Hp2 Hs1 Hs2 Hann_t Hann_f.
exact (L_ms3c_query_digest_no_witness_fields x c1 c2 Hp1 Hp2 Hs1 Hs2 Hann_t Hann_f).
qed.

(* Packaging: the legacy `Hann` hook is redundant with `L_ms3c_ann_digest_list_shape`,
   but kept in the statement so callers (games / obligations) stay stable. *)
lemma L_ms3c_digest_announcement_only (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  forall (c : ms_comparison_clause_surface),
    ms3c_clause_surface_to_payload c = ms3c_phase1_payload_from_public_input x =>
    ms_comparison_clause_simulatable c =>
    c.`mscc_query_digest =
      ms_comparison_query_digest (ms3c_public_stmt_digest x)
        (ms3c_clause_ann_digests_from_surface c).
proof.
move=> _ c Hpayload Hsim.
exact (A_ms3c_query_digest_statement_bound x c Hpayload Hsim).
qed.
