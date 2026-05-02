require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes
  ComparisonPayloadSeeds ComparisonPayloadSupport.

(* False-branch width, simulation on support, and simulatable packaging. *)

axiom A_ms3c_real_constructor_false_index_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.

axiom A_ms3c_sim_constructor_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.

lemma A_ms3c_real_seed_false_index_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
by move=> x sr; exact (A_ms3c_real_constructor_false_index_nonempty x sr).
qed.

lemma A_ms3c_sim_seed_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
by move=> x s ss; exact (A_ms3c_sim_constructor_false_index_nonempty x s ss).
qed.

lemma A_ms3c_real_seed_false_clause_nonempty :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_ann_false.
proof.
move=> x sr.
have Hix_pos := A_ms3c_real_seed_false_index_nonempty x sr.
have Hanchor : ms3c_real_from_seed_public_index_anchor x sr
  by exact (A_ms3c_real_from_seed_uses_public_indices x sr).
have [_ Hshape] := L_ms3c_real_seed_index_shape_valid x sr Hanchor.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_sim_seed_false_clause_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false.
proof.
move=> x s ss.
have Hix_pos := A_ms3c_sim_seed_false_index_nonempty x s ss.
have Hanchor : ms3c_sim_from_seed_public_index_anchor x s ss
  by exact (A_ms3c_sim_from_seed_uses_public_indices x s ss).
have [_ Hshape] := L_ms3c_sim_seed_index_shape_valid x s ss Hanchor.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_false_clauses_hook_implies_schedule_nontrivial :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_false_clauses_payload_schedule_nontrivial x s.
proof.
move=> x s _.
have Hll : is_lossless (d_ms3c_real_payload_seed x).
  exact (L_ms3c_real_payload_seed_lossless x).
have Hmu : mu (d_ms3c_real_payload_seed x) predT <> 0%r.
  rewrite /is_lossless /weight in Hll.
  by rewrite Hll.
have [sr Hsr] : exists (sr : ms3c_real_payload_seed), sr \in d_ms3c_real_payload_seed x.
  have [sr [Hsr _]] := neq0_mu (d_ms3c_real_payload_seed x) predT Hmu.
  by exists sr.
left.
exists (ms3c_real_payload_from_seed x sr).
split.
  rewrite /ms3c_real_payload_on_support /d_ms3c_real_comparison_payload.
  apply supp_dmap.
  by exists sr.
exact (A_ms3c_real_seed_false_clause_nonempty x sr).
qed.

axiom A_ms3c_false_clause_generation_on_support :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_false_clauses_simulated x s.

lemma A_ms3c_false_clause_simulation :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_payload_schedule_nontrivial x s =>
    ms3c_ax_payload_false_clauses_simulated x s.
proof.
by move=> x s _; exact (A_ms3c_false_clause_generation_on_support x s).
qed.

lemma L_ms_comparison_clause_simulatable_of_payload_length_index
  (p : ms3c_comparison_clause_payload) :
  ms3c_payload_length_index_shapes_ok p =>
  ms_comparison_clause_simulatable (ms3c_make_clause_surface p).
proof.
move=> H.
rewrite /ms_comparison_clause_simulatable /ms3c_make_clause_surface /=.
by [].
qed.

lemma L_ms3c_real_payload_support_simulatable (x : ms_public_input) (pr : ms3c_real_comparison_payload) :
  ms3c_real_payload_on_support x pr =>
  ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr).
proof.
move=> Hsup.
apply (L_ms_comparison_clause_simulatable_of_payload_length_index pr).
exact (A_ms3c_real_payload_support_length_index_shapes x pr Hsup).
qed.

lemma L_ms3c_sim_payload_support_simulatable (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload) :
  ms3c_sim_payload_on_support x s ps =>
  ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).
proof.
move=> Hsup.
apply (L_ms_comparison_clause_simulatable_of_payload_length_index ps).
exact (A_ms3c_sim_payload_support_length_index_shapes x s ps Hsup).
qed.
