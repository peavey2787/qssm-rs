require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCouplingTypes
  ComparisonCouplingAxioms ComparisonCouplingMarginals.

lemma L_ms3c_payload_announcement_digests_preserved_from_public_fields
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_public_fields_match x s =>
  ms3c_ax_payload_announcement_digests_preserved x s.
proof.
move=> Hpub pr ps Hpr Hps.
have Hm := Hpub pr ps Hpr Hps.
move: Hm => [_ [_ [Hann_t [Hann_f _]]]].
by rewrite /ms3c_clause_ann_digests_from_surface /ms3c_make_real_clause_surface
  /ms3c_make_sim_clause_surface /ms3c_make_clause_surface
  /ms3c_digest_true_announcement /ms3c_digest_false_announcements /= Hann_t Hann_f.
qed.

lemma A_ms3c_coupling_pair_relation :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_coupling_pair_relation x s.
proof.
move=> x s Hpub Hshr _ Hfalse _.
rewrite /ms3c_ax_payload_coupling_pair_relation => pr ps Hmem.
have [Hpr Hps] := L_ms3c_coupling_mem_components x s pr ps Hmem.
have Hpr' : ms3c_real_payload_on_support x pr by rewrite /ms3c_real_payload_on_support.
have Hps' : ms3c_sim_payload_on_support x s ps by rewrite /ms3c_sim_payload_on_support.
rewrite /ms3c_real_sim_payload_coupled.
split; first by apply (Hpub pr ps Hpr' Hps').
split; first by apply (Hshr pr ps Hpr' Hps').
split.
  have Hdig := L_ms3c_payload_announcement_digests_preserved_from_public_fields x s Hpub.
  by apply (Hdig pr ps Hpr' Hps').
have [Hfa Hfb] := Hfalse.
split; first by apply (Hfa pr Hpr').
by apply (Hfb ps Hps').
qed.

lemma A_ms3c_payload_support_coupling_from_components :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_support_coupling x s.
proof.
move=> x s Hpub Hshr Hcons Hfalse Htrue.
rewrite /ms3c_ax_payload_support_coupling.
split.
  have Hll_sim := L_ms3c_sim_comparison_payload_law_lossless x s.
  have Heq := L_ms3c_coupling_real_projection_eq_payload x s Hll_sim.
  apply (L_ms3c_coupling_real_marginal_eq x s).
    by move=> pr; rewrite Heq.
  by move=> pr Hpr; rewrite -Heq.
split.
  have Hll_real := L_ms3c_real_comparison_payload_law_lossless x.
  have Heq := L_ms3c_coupling_sim_projection_eq_payload x s Hll_real.
  apply (L_ms3c_coupling_sim_marginal_eq x s).
    by move=> ps; rewrite Heq.
  by move=> ps Hps; rewrite -Heq.
exact (A_ms3c_coupling_pair_relation x s Hpub Hshr Hcons Hfalse Htrue).
qed.

lemma L_ms3c_payload_eq_of_coupled
  (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload) :
  ms3c_real_sim_payload_coupled pr ps =>
  pr = ps.
proof.
case: pr=> tr fr atr afr str sfr gcr qdr pcr.
case: ps=> ts fs ats afs sts sfs gcs qds pcs /=.
move=> [Hpub [Hshr _]].
move: Hpub=> [Htr [Hfr [Hatr [Hafr [Hqd [Hgc Hpc]]]]]].
move: Hshr=> [Hstr Hsfr].
by subst.
qed.

lemma L_ms3c_coupling_fst_snd_eq_from_pair_relation
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_coupling_pair_relation x s =>
  d_ms3c_coupling_real_projection x s = d_ms3c_coupling_sim_projection x s.
proof.
move=> Hpair.
rewrite /d_ms3c_coupling_real_projection /d_ms3c_coupling_sim_projection.
apply eq_dmap_in.
move=> [] pr ps Hmem.
have Hcpl := Hpair pr ps Hmem.
exact (L_ms3c_payload_eq_of_coupled pr ps Hcpl).
qed.

lemma A_ms3c_payload_schedule_eq_from_coupling
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_support_coupling x s =>
  d_ms3c_real_comparison_payload x = d_ms3c_sim_comparison_payload x s.
proof.
move=> [Hre [Hsi Hpr]].
have HeqJ := L_ms3c_coupling_fst_snd_eq_from_pair_relation x s Hpr.
by rewrite -Hre HeqJ Hsi.
qed.

lemma L_ms3c_payload_announcements_match_shape_from_ann_hook
  (x : ms_public_input) (s : seed) :
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr)) =>
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps)) =>
  ms3c_ax_payload_announcements_match_shape x s.
proof.
move=> _ _.
exact (L_ms3c_ax_payload_announcements_match_shape_total x s).
qed.

lemma L_ms3c_payload_challenge_share_consistency_from_sum_hook
  (x : ms_public_input) (s : seed) :
  ms3c_clause_challenge_shares_sum x s =>
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr)) =>
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps)) =>
  ms3c_ax_payload_challenge_share_consistency x s.
proof.
move=> Hsum Hreal Hsim.
rewrite /ms3c_ax_payload_challenge_share_consistency /ms3c_payload_programmed_challenge_matches_global.
split.
  move=> pr Hpr.
  by apply (Hsum (ms3c_make_real_clause_surface pr) (Hreal pr Hpr)).
move=> ps Hps.
by apply (Hsum (ms3c_make_sim_clause_surface ps) (Hsim ps Hps)).
qed.

lemma L_ms3c_payload_true_clause_simulated_from_true_hook
  (x : ms_public_input) (s : seed) :
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_ax_payload_true_clause_simulated x s.
proof.
move=> Htrue.
rewrite /ms3c_ax_payload_true_clause_simulated.
split.
  move=> vb tb p r pr _ Hbl Hpos.
  by apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r (ms3c_make_real_clause_surface pr) Hbl Hpos).
move=> vb tb p r ps _ Hbl Hpos.
by apply (A_ms3c_true_clause_from_ms3b_and_schnorr x s Htrue vb tb p r (ms3c_make_sim_clause_surface ps) Hbl Hpos).
qed.

lemma A_ms3c_payload_schedule_equiv :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    d_ms3c_real_comparison_payload x = d_ms3c_sim_comparison_payload x s.
proof.
move=> x s Hann Ha2 Hfalse Htrue Hsum.
have Hreal : forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_comparison_clause_simulatable (ms3c_make_real_clause_surface pr).
  by move=> pr Hpr; apply (L_ms3c_real_payload_support_simulatable x pr Hpr).
have Hsim : forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).
  by move=> ps Hps; apply (L_ms3c_sim_payload_support_simulatable x s ps Hps).
have Hpub := A_ms3c_payload_public_fields_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hshr := A_ms3c_payload_challenge_shares_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hcons :=
  L_ms3c_payload_challenge_share_consistency_from_sum_hook x s Hsum Hreal Hsim.
have Hfalse_nt := A_ms3c_false_clauses_hook_implies_schedule_nontrivial x s Hfalse.
have Hfalse_payload := A_ms3c_false_clause_simulation x s Hfalse_nt.
have Htrue_payload := L_ms3c_payload_true_clause_simulated_from_true_hook x s Htrue.
have Hcpl :=
  A_ms3c_payload_support_coupling_from_components x s
    Hpub Hshr Hcons Hfalse_payload Htrue_payload.
exact (A_ms3c_payload_schedule_eq_from_coupling x s Hcpl).
qed.

lemma A_ms3c_comparison_schedule_equiv :
  forall (x : ms_public_input) (s : seed),
    ms3c_comparison_query_digest_ann_only x s =>
    ms3c_comparison_global_programmable_under_A2 x s =>
    ms3c_false_clauses_simulator_generated x s =>
    ms3c_true_clause_schnorr_from_blinder x s =>
    ms3c_clause_challenge_shares_sum x s =>
    d_ms3c_real_comparison_schedule x = d_ms3c_sim_comparison_schedule x s.
proof.
move=> x s Hann Ha2 Hfalse Htrue Hsum.
have Hp := A_ms3c_payload_schedule_equiv x s Hann Ha2 Hfalse Htrue Hsum.
rewrite /d_ms3c_real_comparison_schedule /d_ms3c_sim_comparison_schedule
  /ms3c_make_real_clause_surface /ms3c_make_sim_clause_surface.
exact (qssm_dmap_congr (d_ms3c_real_comparison_payload x) (d_ms3c_sim_comparison_payload x s)
  ms3c_make_clause_surface Hp).
qed.
