require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCouplingTypes.

lemma L_mu1_eq0_of_notin ['a] (d : 'a distr) (x : 'a) :
  x \notin d => mu1 d x = 0%r.
proof.
move=> hxn.
have Hfwd :=
  iffLR (x \notin d) (mu1 d x = 0%r) (supportPn d x).
exact (Hfwd hxn).
qed.

lemma L_mu1_eq0_of_nmem ['a] (d : 'a distr) (x : 'a) :
  !(x \in d) => mu1 d x = 0%r.
proof.
move=> hxn.
exact (L_mu1_eq0_of_notin d x hxn).
qed.

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

lemma L_ms3c_coupling_real_marginal_eq (x : ms_public_input) (s : seed) :
  (forall (pr : ms3c_real_comparison_payload),
    pr \in d_ms3c_coupling_real_projection x s <=>
    pr \in d_ms3c_real_comparison_payload x) =>
  (forall (pr : ms3c_real_comparison_payload),
    pr \in d_ms3c_real_comparison_payload x =>
    mu1 (d_ms3c_coupling_real_projection x s) pr =
    mu1 (d_ms3c_real_comparison_payload x) pr) =>
  d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x.
proof.
move=> Hs Hmu; apply eq_distr => pr.
case (pr \in d_ms3c_real_comparison_payload x) => [Hin|Hn2].
  exact (Hmu pr Hin).
have ->: mu1 (d_ms3c_real_comparison_payload x) pr = 0%r.
  exact (L_mu1_eq0_of_notin (d_ms3c_real_comparison_payload x) pr Hn2).
have hpq := iffLR (pr \in d_ms3c_coupling_real_projection x s)
  (pr \in d_ms3c_real_comparison_payload x) (Hs pr).
have Hneg : !(pr \in d_ms3c_coupling_real_projection x s).
  exact (contra (pr \in d_ms3c_coupling_real_projection x s)
    (pr \in d_ms3c_real_comparison_payload x) hpq Hn2).
have ->: mu1 (d_ms3c_coupling_real_projection x s) pr = 0%r.
  exact (L_mu1_eq0_of_nmem (d_ms3c_coupling_real_projection x s) pr Hneg).
by [].
qed.

lemma L_ms3c_coupling_sim_marginal_eq (x : ms_public_input) (s : seed) :
  (forall (ps : ms3c_sim_comparison_payload),
    ps \in d_ms3c_coupling_sim_projection x s <=>
    ps \in d_ms3c_sim_comparison_payload x s) =>
  (forall (ps : ms3c_sim_comparison_payload),
    ps \in d_ms3c_sim_comparison_payload x s =>
    mu1 (d_ms3c_coupling_sim_projection x s) ps =
    mu1 (d_ms3c_sim_comparison_payload x s) ps) =>
  d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s.
proof.
move=> Hs Hmu; apply eq_distr => ps.
case (ps \in d_ms3c_sim_comparison_payload x s) => [Hin|Hn2].
  exact (Hmu ps Hin).
have ->: mu1 (d_ms3c_sim_comparison_payload x s) ps = 0%r.
  exact (L_mu1_eq0_of_notin (d_ms3c_sim_comparison_payload x s) ps Hn2).
have hpq := iffLR (ps \in d_ms3c_coupling_sim_projection x s)
  (ps \in d_ms3c_sim_comparison_payload x s) (Hs ps).
have Hneg : !(ps \in d_ms3c_coupling_sim_projection x s).
  exact (contra (ps \in d_ms3c_coupling_sim_projection x s)
    (ps \in d_ms3c_sim_comparison_payload x s) hpq Hn2).
have ->: mu1 (d_ms3c_coupling_sim_projection x s) ps = 0%r.
  exact (L_mu1_eq0_of_nmem (d_ms3c_coupling_sim_projection x s) ps Hneg).
by [].
qed.

lemma L_dmap_dprod_fst_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
rewrite (dprod_marginalL da db (fun (a : 'a) => a)).
rewrite dmap_id.
have Hw: weight db = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma L_dmap_dprod_snd_lossless ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw: weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma L_ms3c_coupling_real_projection_eq_payload (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_comparison_payload x s) =>
  d_ms3c_coupling_real_projection x s = d_ms3c_real_comparison_payload x.
proof.
move=> Hll.
rewrite /d_ms3c_coupling_real_projection /d_ms3c_real_sim_payload_coupling.
exact (L_dmap_dprod_fst_lossless (d_ms3c_real_comparison_payload x) (d_ms3c_sim_comparison_payload x s) Hll).
qed.

lemma L_ms3c_coupling_sim_projection_eq_payload (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_real_comparison_payload x) =>
  d_ms3c_coupling_sim_projection x s = d_ms3c_sim_comparison_payload x s.
proof.
move=> Hll.
rewrite /d_ms3c_coupling_sim_projection /d_ms3c_real_sim_payload_coupling.
exact (L_dmap_dprod_snd_lossless (d_ms3c_real_comparison_payload x) (d_ms3c_sim_comparison_payload x s) Hll).
qed.
