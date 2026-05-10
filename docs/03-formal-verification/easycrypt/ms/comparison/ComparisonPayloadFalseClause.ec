require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes
  ComparisonPayloadSeeds ComparisonPayloadSupport.

(* False-branch width, simulation on support, and simulatable packaging. *)

lemma L_ms3c_real_constructor_false_index_nonempty (x : ms_public_input) (sr : ms3c_real_payload_seed) :
  ms3c_public_false_branch_nonempty x =>
  ms3c_real_from_seed_public_index_anchor x sr =>
  0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
move=> Hnb [Hixs _].
have -> : size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs =
           size (ms3c_public_false_clause_indices x).
  by rewrite Hixs.
move: Hnb.
rewrite /ms3c_public_false_branch_nonempty /ms3c_public_false_branch_count.
rewrite /ms3c_public_false_clause_indices /ms_public_comparison_false_indices.
rewrite /ms_public_comparison_false_entries.
by rewrite size_map.
qed.

lemma L_ms3c_sim_constructor_false_index_nonempty
  (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed) :
  ms3c_public_false_branch_nonempty x =>
  ms3c_sim_from_seed_public_index_anchor x s ss =>
  0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
move=> Hnb [Hixs _].
have -> : size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs =
           size (ms3c_public_false_clause_indices x).
  by rewrite Hixs.
move: Hnb.
rewrite /ms3c_public_false_branch_nonempty /ms3c_public_false_branch_count.
rewrite /ms3c_public_false_clause_indices /ms_public_comparison_false_indices.
rewrite /ms_public_comparison_false_entries.
by rewrite size_map.
qed.

lemma A_ms3c_real_seed_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (sr : ms3c_real_payload_seed),
    ms3c_false_clauses_simulator_generated x s =>
    sr \in d_ms3c_real_payload_seed x =>
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.
proof.
move=> x s sr [Hnb _] Hsr.
exact (L_ms3c_real_constructor_false_index_nonempty x sr
  Hnb
  (A_ms3c_real_from_seed_uses_public_indices x sr Hsr)).
qed.

lemma A_ms3c_sim_seed_false_index_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_false_clauses_simulator_generated x s =>
    ss \in d_ms3c_sim_payload_seed x s =>
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.
proof.
move=> x s ss [Hnb _] Hss.
exact (L_ms3c_sim_constructor_false_index_nonempty x s ss
  Hnb
  (A_ms3c_sim_from_seed_uses_public_indices x s ss Hss)).
qed.

lemma A_ms3c_real_seed_false_clause_nonempty :
  forall (x : ms_public_input) (s : seed) (sr : ms3c_real_payload_seed),
    ms3c_false_clauses_simulator_generated x s =>
    sr \in d_ms3c_real_payload_seed x =>
    0 < size (ms3c_real_payload_from_seed x sr).`mscp_ann_false.
proof.
move=> x s sr Hfalse Hsr.
have Hix_pos := A_ms3c_real_seed_false_index_nonempty x s sr Hfalse Hsr.
have Hanchor : ms3c_real_from_seed_public_index_anchor x sr
  by exact (A_ms3c_real_from_seed_uses_public_indices x sr Hsr).
have [_ Hshape] := L_ms3c_real_seed_index_shape_valid x sr Hsr.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_sim_seed_false_clause_nonempty :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    ms3c_false_clauses_simulator_generated x s =>
    ss \in d_ms3c_sim_payload_seed x s =>
    0 < size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false.
proof.
move=> x s ss Hfalse Hss.
have Hix_pos := A_ms3c_sim_seed_false_index_nonempty x s ss Hfalse Hss.
have Hanchor : ms3c_sim_from_seed_public_index_anchor x s ss
  by exact (A_ms3c_sim_from_seed_uses_public_indices x s ss Hss).
have [_ Hshape] := L_ms3c_sim_seed_index_shape_valid x s ss Hss.
rewrite Hshape.
exact Hix_pos.
qed.

lemma A_ms3c_false_clauses_hook_implies_schedule_nontrivial :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_false_clauses_payload_schedule_nontrivial x s.
proof.
move=> x s Hfalse.
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
exact (A_ms3c_real_seed_false_clause_nonempty x s sr Hfalse Hsr).
qed.

(* Payloads on support now agree with `ms3c_phase1_payload_from_public_input x` only at
   the folded comparison surface. The false-clause proof uses that surface equality,
   so payload-only sampled-coin fields can vary without affecting the simulator law. *)
lemma A_ms3c_real_false_announcements_match_shares_on_support :
  forall (x : ms_public_input) (s : seed) (pr : ms3c_real_comparison_payload),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_real_payload_on_support x pr =>
    ms_false_clause_simulated (ms3c_make_real_clause_surface pr).
proof.
move=> x s pr [_ Hsim] Hsup.
rewrite (L_ms3c_real_payload_on_support_eq_phase1 x pr Hsup).
exact (L_ms_false_clause_simulated_phase1_from_public_input x Hsim).
qed.

lemma A_ms3c_sim_false_announcements_match_shares_on_support :
  forall (x : ms_public_input) (s : seed) (ps : ms3c_sim_comparison_payload),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_sim_payload_on_support x s ps =>
    ms_false_clause_simulated (ms3c_make_sim_clause_surface ps).
proof.
move=> x s ps [_ Hsim] Hsup.
rewrite (L_ms3c_sim_payload_on_support_eq_phase1 x s ps Hsup).
exact (L_ms_false_clause_simulated_phase1_from_public_input x Hsim).
qed.

lemma L_ms3c_false_clause_generation_on_support (x : ms_public_input) (s : seed) :
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_ax_payload_false_clauses_simulated x s.
proof.
move=> Hfalse.
rewrite /ms3c_ax_payload_false_clauses_simulated /=.
split.
  by move=> pr Hsup; apply (A_ms3c_real_false_announcements_match_shares_on_support x s pr Hfalse Hsup).
by move=> ps Hsup; apply (A_ms3c_sim_false_announcements_match_shares_on_support x s ps Hfalse Hsup).
qed.

lemma A_ms3c_false_clause_simulation :
  forall (x : ms_public_input) (s : seed),
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_false_clauses_payload_schedule_nontrivial x s =>
    ms3c_ax_payload_false_clauses_simulated x s.
proof.
by move=> x s Hfalse _; exact (L_ms3c_false_clause_generation_on_support x s Hfalse).
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
