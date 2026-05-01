require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem.

lemma L_ms3c_rom_scalar_response_for_any_digest (x : ms_public_input) (s : seed) :
  ms3c_comparison_global_programmable_under_A2 x s =>
  forall (qd : digest), exists (t : scalar), ms_query_to_scalar qd = t.
proof.
rewrite /ms3c_comparison_global_programmable_under_A2 /ms3c_programmed_comparison_rom_ready.
by move=> Hrom qd; case: (Hrom qd) => t Ht; exists t.
qed.

lemma MS_3c_comparison_clause_obligations (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  (forall (stmt : digest) (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    c.`mscc_query_digest = ms_comparison_query_digest stmt (ms3c_clause_ann_digests_from_surface c)) /\
  ((forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_false_clause_simulated (ms3c_make_real_clause_surface pr)) /\
   (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_false_clause_simulated (ms3c_make_sim_clause_surface ps))) /\
  (forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
    ms_true_clause_simulates_from_blinder_points vb tb p r c =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder c.`mscc_ann_true true r) /\
  (forall (c : ms_comparison_clause_surface),
    ms_comparison_clause_simulatable c =>
    ms_comparison_challenges_split c).
proof.
move=> Hann Hfalse Htrue Hsum.
split; first by move=> stmt c Hsim; apply (L_ms3c_digest_announcement_only x s Hann stmt c Hsim).
split.
  have Hfalse_nt := A_ms3c_false_clauses_hook_implies_schedule_nontrivial x s Hfalse.
  move: (A_ms3c_false_clause_simulation x s Hfalse_nt).
  rewrite /ms3c_ax_payload_false_clauses_simulated; case=> Hfr Hfs.
  split; first by move=> pr Hpr; apply (Hfr pr Hpr).
  by move=> ps Hps; apply (Hfs ps Hps).
split; first by move=> vb tb p r c Hbl Hpos; apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r c Hbl Hpos).
by move=> c Hsim; apply (A_ms3c_challenge_share_sum x s Hsum c Hsim).
qed.

lemma MS_3c_exact_comparison_simulation_from_clauses (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_comparison_global_programmable_under_A2 x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  ms_comparison_exact_simulation_equiv x s.
proof.
move=> Hann Ha2 Hfalse Htrue Hsum.
have Heq := A_ms3c_comparison_schedule_equiv x s Hann Ha2 Hfalse Htrue Hsum.
have _ := L_ms3c_rom_scalar_response_for_any_digest x s Ha2.
exact (ms_comparison_exact_simulation_equiv_of_schedule_eq x s Heq).
qed.
