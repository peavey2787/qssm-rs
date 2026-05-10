require import AllCore Int List Distr.
import Ring.IntID StdOrder.IntOrder.

lemma drange_pred_true_mass (total : int) (p : int -> bool) :
  0 < total =>
  mu1 (dmap (drange 0 total) p) true =
  (count p (range 0 total))%r / total%r.
proof.
move=> Htotal_pos.
rewrite /mu1 dmapE /=.
have Heq :
    mu (drange 0 total) (fun slot : int => pred1 true (p slot)) =
    mu (drange 0 total) (fun slot : int => p slot).
  apply mu_eq=> slot /=.
  by rewrite /pred1; case (p slot).
rewrite Heq.
rewrite drangeE.
have -> : total - 0 = total by ring.
by [].
qed.

lemma drange_pred_true_mass_le_bound (bound total : int) (p : int -> bool) :
  0 < total =>
  count p (range 0 total) <= bound =>
  mu1 (dmap (drange 0 total) p) true <=
  bound%r / total%r.
proof.
move=> Htotal_pos Hcount_bound.
rewrite (drange_pred_true_mass total p Htotal_pos).
by smt().
qed.

lemma drange_subset_true_mass (total : int) (subset : int list) :
  0 < total =>
  mu1 (dmap (drange 0 total) (fun slot : int => slot \in subset)) true =
  (count (fun slot : int => slot \in subset) (range 0 total))%r / total%r.
proof.
move=> Htotal_pos.
exact (drange_pred_true_mass total (fun slot : int => slot \in subset) Htotal_pos).
qed.

lemma drange_subset_true_mass_le_bound (bound total : int) (subset : int list) :
  0 < total =>
  count (fun slot : int => slot \in subset) (range 0 total) <= bound =>
  mu1 (dmap (drange 0 total) (fun slot : int => slot \in subset)) true <=
  bound%r / total%r.
proof.
move=> Htotal_pos Hcount_bound.
exact (drange_pred_true_mass_le_bound bound total
  (fun slot : int => slot \in subset) Htotal_pos Hcount_bound).
qed.

lemma drange_subset_complement_mass (total : int) (subset : int list) :
  0 < total =>
  mu1 (dmap (drange 0 total) (fun slot : int => slot \in subset)) false =
  (total - count (fun slot : int => slot \in subset) (range 0 total))%r / total%r.
proof.
move=> Htotal_pos.
pose d := dmap (drange 0 total) (fun slot : int => slot \in subset).
have Hll : is_lossless d.
  rewrite /d.
  apply dmap_ll.
  apply drange_ll.
  exact Htotal_pos.
have Hfalse :
    mu d (fun bad : bool => ! bad) = mu1 d false.
  apply/mu_eq=> bad /=.
  by case: bad.
have Htrue :
    mu d (fun bad : bool => bad) = mu1 d true.
  apply/mu_eq=> bad /=.
  by case: bad.
have Hnot :
    mu d (fun bad : bool => ! bad) =
    mu d predT - mu d (fun bad : bool => bad).
  by rewrite mu_not /weight.
rewrite -Hfalse Hnot Htrue.
have Hw : weight d = 1%r.
  exact (is_losslessP _ Hll).
rewrite Hw /d.
rewrite (drange_subset_true_mass total subset Htotal_pos).
by smt().
qed.

lemma count_range0_lt_prefix (bound total : int) :
  0 <= bound =>
  bound <= total =>
  count (fun slot : int => slot < bound) (range 0 total) = bound.
proof.
move=> Hbound_nonneg Hbound_le_total.
have Hsplit : range 0 total = range 0 bound ++ range bound total.
  by apply (range_cat bound 0 total).
rewrite Hsplit count_cat.
have Hpre :
    count (fun slot : int => slot < bound) (range 0 bound) =
    size (range 0 bound).
  apply count_predT_eq_in=> slot Hslot.
  by smt(mem_range).
have Hsuf :
    count (fun slot : int => slot < bound) (range bound total) = 0.
  apply count_pred0_eq_in=> slot Hslot.
  by smt(mem_range).
rewrite Hpre Hsuf.
rewrite size_range.
by smt().
qed.

lemma drange_prefix_true_mass (bound total : int) :
  0 <= bound =>
  bound <= total =>
  0 < total =>
  mu1 (dmap (drange 0 total) (fun slot : int => slot < bound)) true =
  bound%r / total%r.
proof.
move=> Hbound_nonneg Hbound_le_total Htotal_pos.
rewrite /mu1 dmapE /=.
have Heq :
    mu (drange 0 total) (fun slot : int => pred1 true (slot < bound)) =
    mu (drange 0 total) (fun slot : int => slot < bound).
  apply mu_eq=> slot /=.
  by rewrite /pred1; case (slot < bound).
rewrite Heq.
rewrite drangeE.
rewrite (count_range0_lt_prefix bound total Hbound_nonneg Hbound_le_total).
have ->: total - 0 = total by ring.
by [].
qed.

lemma count_range0_interval (lower upper total : int) :
  0 <= lower =>
  lower <= upper =>
  upper <= total =>
  count (fun slot : int => lower <= slot /\ slot < upper) (range 0 total) =
  upper - lower.
proof.
move=> Hlower_nonneg Hlower_le_upper Hupper_le_total.
have Hsplit1 : range 0 total = range 0 lower ++ range lower total.
  have Hlower_le_total : lower <= total by smt().
  apply (range_cat lower 0 total).
  exact Hlower_nonneg.
  exact Hlower_le_total.
have Hsplit2 : range lower total = range lower upper ++ range upper total.
  apply (range_cat upper lower total).
  exact Hlower_le_upper.
  exact Hupper_le_total.
rewrite Hsplit1 count_cat Hsplit2 count_cat.
have Hpre :
    count (fun slot : int => lower <= slot /\ slot < upper) (range 0 lower) = 0.
  apply count_pred0_eq_in=> slot Hslot.
  by smt(mem_range).
have Hmid :
    count (fun slot : int => lower <= slot /\ slot < upper) (range lower upper) =
    size (range lower upper).
  apply count_predT_eq_in=> slot Hslot.
  by smt(mem_range).
have Hsuf :
    count (fun slot : int => lower <= slot /\ slot < upper) (range upper total) = 0.
  apply count_pred0_eq_in=> slot Hslot.
  by smt(mem_range).
rewrite Hpre Hmid Hsuf.
rewrite size_range.
by smt().
qed.

lemma drange_interval_true_mass (lower upper total : int) :
  0 <= lower =>
  lower <= upper =>
  upper <= total =>
  0 < total =>
  mu1 (dmap (drange 0 total)
    (fun slot : int => lower <= slot /\ slot < upper)) true =
  (upper - lower)%r / total%r.
proof.
move=> Hlower_nonneg Hlower_le_upper Hupper_le_total Htotal_pos.
rewrite /mu1 dmapE /=.
have Heq :
    mu (drange 0 total)
      (fun slot : int => pred1 true (lower <= slot /\ slot < upper)) =
    mu (drange 0 total)
      (fun slot : int => lower <= slot /\ slot < upper).
  apply mu_eq=> slot /=.
  by rewrite /pred1; case (lower <= slot /\ slot < upper).
rewrite Heq.
rewrite drangeE.
rewrite (count_range0_interval lower upper total
  Hlower_nonneg Hlower_le_upper Hupper_le_total).
have -> : total - 0 = total by ring.
by [].
qed.
