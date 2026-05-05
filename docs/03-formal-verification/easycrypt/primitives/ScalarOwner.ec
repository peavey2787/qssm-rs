require import AllCore List Distr.
require ActionOwner.

type scalar = ActionOwner.scalar.

clone export ActionOwner.ScalarRing as ScalarRing.

op scalar_add : scalar -> scalar -> scalar = ActionOwner.scalar_add.

op scalar_opp : scalar -> scalar = ActionOwner.scalar_opp.

op scalar_sub (x y : scalar) : scalar =
  ActionOwner.scalar_sub x y.

op scalar_mul : scalar -> scalar -> scalar = ActionOwner.scalar_mul.

op scalar_translate (alpha t : scalar) : scalar =
  ActionOwner.scalar_translate alpha t.

op scalar_enum : scalar list = ActionOwner.scalar_enum.

op scalar_card : int = ActionOwner.scalar_card.

op scalar_uniform : scalar distr = ActionOwner.scalar_uniform.

lemma scalar_enumP (x : scalar) :
  x \in scalar_enum.
proof. exact (ActionOwner.scalar_enumP x). qed.

lemma scalar_enum_uniq :
  uniq scalar_enum.
proof. exact ActionOwner.scalar_enum_uniq. qed.

lemma scalar_cardE :
  scalar_card = 17.
proof. exact ActionOwner.scalar_cardE. qed.

lemma scalar_uniform_eq_duniform :
  scalar_uniform = duniform scalar_enum.
proof. exact ActionOwner.scalar_uniform_eq_duniform. qed.

lemma scalar_uniform_lossless :
  is_lossless scalar_uniform.
proof. exact ActionOwner.scalar_uniform_lossless. qed.

lemma scalar_translate_inj (t x y : scalar) :
  x \in scalar_enum =>
  y \in scalar_enum =>
  scalar_translate x t = scalar_translate y t =>
  x = y.
proof. exact (ActionOwner.scalar_translate_inj t x y). qed.

lemma scalar_translate_surj (t x : scalar) :
  x \in map (fun alpha => scalar_translate alpha t) scalar_enum.
proof. exact (ActionOwner.scalar_translate_surj t x). qed.

lemma scalar_uniform_invariant_add (t : scalar) :
  dlet scalar_uniform (fun alpha => dunit (scalar_translate alpha t)) =
  scalar_uniform.
proof. exact (ActionOwner.scalar_uniform_invariant_add t). qed.