require import AllCore Int List Distr.
import Ring.IntID StdOrder.IntOrder.

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
