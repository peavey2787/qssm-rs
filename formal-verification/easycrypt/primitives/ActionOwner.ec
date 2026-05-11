require import AllCore List Distr IntDiv.
require Group ZModP.

import Ring.IntID StdOrder.IntOrder.

clone import ZModP.ZModRing as RawScalar with
  op p <- 17
  proof ge2_p by smt().

type scalar = RawScalar.zmod.
type point = scalar.

clone export RawScalar.ZModpRing as ScalarRing with
  type t <- scalar.

clone import Group.CyclicGroup as PointGroup with
  type group <- point,
  op   elems <- map RawScalar.inzmod (range 0 17),
  op   e     =  RawScalar.zero,
  op   ( * ) =  RawScalar.( + ),
  op   inv   =  RawScalar.([-]),
  op   g     =  RawScalar.one
  proof *.

realize elems_spec.
move=> x; rewrite count_uniq_mem 2:b2i_eq1; last first.
+ apply/mapP => /=; exists (asint x).
  by rewrite mem_range rg_asint asintK.
rewrite map_inj_in_uniq ?range_uniq // => {x} x y.
rewrite !mem_range => rgx rgy /= /(congr1 asint).
by rewrite !inzmodK !pmod_small.
qed.

realize mulcC by apply: RawScalar.ZModpRing.addrC.
realize mul1c by apply: RawScalar.ZModpRing.add0r.
realize mulcA by apply: RawScalar.ZModpRing.addrA.
realize mulVc by apply: RawScalar.ZModpRing.addNr.

realize monogenous.
proof.
move=> x; exists (asint x) => @/g; rewrite {1}(intmul_asint x).
rewrite /intmul /(^) ltrNge ge0_asint /=.
by rewrite AddMonoid.iteropE /(^+) ger0_norm ?ge0_asint.
qed.

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

op point_neutral : point = PointGroup.e.

op point_opp : point -> point = PointGroup.inv.

op point_add : point -> point -> point = PointGroup.( * ).

op point_generator : point = PointGroup.g.

op point_smul (s : scalar) (P : point) : point =
  scalar_mul s P.

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

lemma point_smul_add (s t : scalar) (P : point) :
  point_smul (scalar_add s t) P =
  point_add (point_smul s P) (point_smul t P).
proof.
rewrite /point_smul /scalar_add /point_add.
exact (ScalarRing.mulrDl s t P).
qed.

lemma point_smul_mul (c w : scalar) (P : point) :
  point_smul (scalar_mul c w) P =
  point_smul c (point_smul w P).
proof.
apply/RawScalar.asint_inj.
rewrite /point_smul /scalar_mul !RawScalar.mulE.
by rewrite modzMml modzMmr mulzA.
qed.

lemma action_add_gen (s t : scalar) :
  point_smul (scalar_add s t) point_generator =
  point_add (point_smul s point_generator) (point_smul t point_generator).
proof. exact (point_smul_add s t point_generator). qed.

lemma action_mul_embed (c w : scalar) :
  point_smul (scalar_mul c w) point_generator =
  point_smul c (point_smul w point_generator).
proof. exact (point_smul_mul c w point_generator). qed.