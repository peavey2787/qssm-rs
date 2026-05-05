require import AllCore List Distr.
require ZModP.

clone import ZModP.ZModRing as RawScalar with
  op p <- 17
  proof ge2_p by smt().

type scalar = RawScalar.zmod.

clone export RawScalar.ZModpRing as ScalarRing with
  type t <- scalar.

op scalar_add : scalar -> scalar -> scalar = ScalarRing.( + ).

op scalar_opp : scalar -> scalar = ScalarRing.([-]).

op scalar_sub (x y : scalar) : scalar =
  x - y.

op scalar_mul : scalar -> scalar -> scalar = ScalarRing.( * ).

op scalar_translate (alpha t : scalar) : scalar =
  scalar_add alpha t.

op scalar_enum : scalar list = RawScalar.DZmodP.Support.enum.

op scalar_card : int = RawScalar.DZmodP.Support.card.

op scalar_uniform : scalar distr = RawScalar.DZmodP.dunifin.

lemma scalar_enumP (x : scalar) :
  x \in scalar_enum.
proof. exact (RawScalar.DZmodP.Support.enumP x). qed.

lemma scalar_enum_uniq :
  uniq scalar_enum.
proof. exact RawScalar.DZmodP.Support.enum_uniq. qed.

lemma scalar_cardE :
  scalar_card = 17.
proof. exact RawScalar.DZmodP.cardE. qed.

lemma scalar_uniform_eq_duniform :
  scalar_uniform = duniform scalar_enum.
proof. by rewrite /scalar_uniform /scalar_enum. qed.

lemma scalar_uniform_lossless :
  is_lossless scalar_uniform.
proof. exact RawScalar.DZmodP.dunifin_ll. qed.

lemma scalar_translate_inj (t x y : scalar) :
  x \in scalar_enum =>
  y \in scalar_enum =>
  scalar_translate x t = scalar_translate y t =>
  x = y.
proof.
move=> xs ys eq_xy.
exact (ScalarRing.addIr t x y eq_xy).
qed.

lemma scalar_translate_surj (t x : scalar) :
  x \in map (fun alpha => scalar_translate alpha t) scalar_enum.
proof.
have Hmem :
  scalar_translate (scalar_sub x t) t \in
  map (fun alpha => scalar_translate alpha t) scalar_enum.
  apply (map_f (fun alpha => scalar_translate alpha t) scalar_enum).
  exact (scalar_enumP (scalar_sub x t)).
suff <- : scalar_translate (scalar_sub x t) t = x by exact Hmem.
by rewrite /scalar_translate /scalar_sub /scalar_add; exact (ScalarRing.subrK x t).
qed.

lemma scalar_uniform_invariant_add (t : scalar) :
  dlet scalar_uniform (fun alpha => dunit (scalar_translate alpha t)) =
  scalar_uniform.
proof.
have Hmap :
    dmap scalar_uniform (fun alpha => scalar_translate alpha t) =
    duniform (map (fun alpha => scalar_translate alpha t) scalar_enum).
  rewrite scalar_uniform_eq_duniform.
  apply dmap_duniform.
  exact (scalar_translate_inj t).
have Hsame :
    duniform (map (fun alpha => scalar_translate alpha t) scalar_enum) =
    duniform scalar_enum.
  apply/eq_duniformP => x; split.
  - move=> _; exact (scalar_enumP x).
  move=> _; exact (scalar_translate_surj t x).
have Hdmap :
    dlet scalar_uniform (fun alpha => dunit (scalar_translate alpha t)) =
    dmap scalar_uniform (fun alpha => scalar_translate alpha t).
  by [].
rewrite Hdmap.
rewrite Hmap.
rewrite Hsame.
rewrite /scalar_uniform /scalar_enum.
by [].
qed.