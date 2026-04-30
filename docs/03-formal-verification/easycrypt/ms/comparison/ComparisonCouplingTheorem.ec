require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCouplingTypes ComparisonCouplingAxioms.

lemma L_ms3c_true_clause_schnorr_equiv_from_ms3a
  (x : ms_public_input) (s : seed) :
  ms3c_true_clause_schnorr_equiv x s.
proof.
move=> vb tb p r c _.
exact (MS_3a_single_branch_schnorr_reparam r (ms_query_to_scalar c.`mscc_programmed_challenge)).
qed.

lemma A_ms3c_true_clause_from_ms3b_and_schnorr :
  forall (x : ms_public_input) (s : seed),
    ms3c_true_clause_schnorr_from_blinder x s =>
    forall (vb : bool list) (tb : bool list) (p : int) (r : scalar) (c : ms_comparison_clause_surface),
      ms_true_clause_simulates_from_blinder_points vb tb p r c =>
      ms_true_clause_position vb tb p =>
      ms_clause_public_point_matches_blinder c.`mscc_ann_true true r.
proof.
move=> x s [Hms3b [Hreparam Htrue]] vb tb p r c Hbl Hpos.
have [Hop [Hhd Hob]] := Hms3b vb tb p r c Hpos.
have Hms3bTrue :=
  MS_3b_true_clause_characterization x vb tb p c.`mscc_ann_true r Hop Hhd Hpos Hob.
have Hsch := Hreparam vb tb p r c Hpos.
have _ := Hsch.
rewrite /ms_true_clause_points_are_blinder_points in Hms3bTrue.
exact (Hms3bTrue Hpos).
qed.

lemma A_ms3c_challenge_share_sum :
  forall (x : ms_public_input) (s : seed),
    ms3c_clause_challenge_shares_sum x s =>
    forall (c : ms_comparison_clause_surface),
      ms_comparison_clause_simulatable c =>
      ms_comparison_challenges_split c.
proof.
move=> x s Hsum c Hsim.
rewrite /ms_comparison_challenges_split /ms3c_clause_shares_sum_matches_global.
have Hpg := Hsum c Hsim.
move: Hsim => [_ [Hann_sh Hann_fx]].
split.
  by rewrite -Hann_sh Hann_fx.
split.
  by rewrite eq_sym Hann_sh.
by rewrite Hpg.
qed.

lemma A_ms3c_payload_support_coupling_from_components :
  forall (x : ms_public_input) (s : seed),
    ms3c_ax_payload_public_fields_match x s =>
    ms3c_ax_payload_challenge_shares_match x s =>
    ms3c_ax_payload_announcement_digests_preserved x s =>
    ms3c_ax_payload_announcements_match_shape x s =>
    ms3c_ax_payload_challenge_share_consistency x s =>
    ms3c_ax_payload_false_clauses_simulated x s =>
    ms3c_ax_payload_true_clause_simulated x s =>
    ms3c_ax_payload_support_coupling x s.
proof.
move=> x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue.
rewrite /ms3c_ax_payload_support_coupling.
split.
  exact (A_ms3c_coupling_real_marginal x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
split.
  exact (A_ms3c_coupling_sim_marginal x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
exact (A_ms3c_coupling_pair_relation x s Hpub Hshr Hann_dig Hann_sh Hcons Hfalse Htrue).
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
move=> Hreal Hsim.
rewrite /ms3c_ax_payload_announcements_match_shape /ms3c_payload_ann_digest_list_shape_ok.
split.
  move=> pr Hpr.
  exact (L_ms3c_ann_digest_list_shape (ms3c_make_real_clause_surface pr)).
move=> ps Hps.
exact (L_ms3c_ann_digest_list_shape (ms3c_make_sim_clause_surface ps)).
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
  by move=> pr Hpr; apply (A_ms3c_real_payload_support_simulatable x pr Hpr).
have Hsim : forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_comparison_clause_simulatable (ms3c_make_sim_clause_surface ps).
  by move=> ps Hps; apply (A_ms3c_sim_payload_support_simulatable x s ps Hps).
have Hpub := A_ms3c_payload_public_fields_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hshr := A_ms3c_payload_challenge_shares_match x s Hann Ha2 Hfalse Htrue Hsum.
have Hann_dig :=
  L_ms3c_payload_announcement_digests_preserved_from_public_fields x s Hpub.
have Hann_shape :=
  L_ms3c_payload_announcements_match_shape_from_ann_hook x s Hreal Hsim.
have Hcons :=
  L_ms3c_payload_challenge_share_consistency_from_sum_hook x s Hsum Hreal Hsim.
have Hfalse_payload := A_ms3c_false_clause_simulation x s Hfalse.
have Htrue_payload := L_ms3c_payload_true_clause_simulated_from_true_hook x s Htrue.
have Hcpl :=
  A_ms3c_payload_support_coupling_from_components x s
    Hpub Hshr Hann_dig Hann_shape Hcons Hfalse_payload Htrue_payload.
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
