require import AllCore Distr.
require import QssmTypes.
require PointInterface.

(* Permanent algebra model (abstract scalar / point group + homomorphism on the fixed generator). *)

op sch_generator : sch_point.
op sch_neutral_pt : sch_point = PointInterface.sch_neutral_pt.
op sch_opp_pt : sch_point -> sch_point = PointInterface.sch_opp_pt.
op sch_add_pt : sch_point -> sch_point -> sch_point = PointInterface.sch_add_pt.

op sch_sub_pt (x y : sch_point) : sch_point =
  sch_add_pt x (sch_opp_pt y).

op sch_smul : scalar -> sch_point -> sch_point.

op sch_s_add : scalar -> scalar -> scalar.
op sch_s_sub : scalar -> scalar -> scalar.
op sch_s_mul : scalar -> scalar -> scalar.

(* P = w * H *)
op sch_pubkey (w : scalar) : sch_point = sch_smul w sch_generator.

(* Scalar group fragment (needed for Schnorr algebra on exponents) *)

axiom sch_s_addA (x y z : scalar) :
  sch_s_add x (sch_s_add y z) = sch_s_add (sch_s_add x y) z.

axiom sch_s_addC (x y : scalar) :
  sch_s_add x y = sch_s_add y x.

axiom sch_s_sub_def (x y : scalar) :
  sch_s_add (sch_s_sub x y) y = x.

axiom sch_s_mul_add_distr (c w1 w2 : scalar) :
  sch_s_mul c (sch_s_add w1 w2) = sch_s_add (sch_s_mul c w1) (sch_s_mul c w2).

(* Point group fragment + homomorphism at H *)

lemma sch_addA (x y z : sch_point) :
  sch_add_pt x (sch_add_pt y z) = sch_add_pt (sch_add_pt x y) z.
proof. exact (PointInterface.sch_addA x y z). qed.

lemma sch_addC (x y : sch_point) :
  sch_add_pt x y = sch_add_pt y x.
proof. exact (PointInterface.sch_addC x y). qed.

lemma sch_neutralL (x : sch_point) :
  sch_add_pt sch_neutral_pt x = x.
proof. exact (PointInterface.sch_neutralL x). qed.

lemma sch_oppL (x : sch_point) :
  sch_add_pt (sch_opp_pt x) x = sch_neutral_pt.
proof. exact (PointInterface.sch_oppL x). qed.

axiom sch_smul_add_gen (s t : scalar) :
  sch_smul (sch_s_add s t) sch_generator =
  sch_add_pt (sch_smul s sch_generator) (sch_smul t sch_generator).

axiom sch_smul_mul_embed (c w : scalar) :
  sch_smul (sch_s_mul c w) sch_generator =
  sch_smul c (sch_smul w sch_generator).

lemma sch_neutralR (x : sch_point) :
  sch_add_pt x sch_neutral_pt = x.
proof.
by rewrite sch_addC sch_neutralL.
qed.

lemma sch_add_pt_oppR (y : sch_point) :
  sch_add_pt y (sch_opp_pt y) = sch_neutral_pt.
proof.
by rewrite sch_addC sch_oppL.
qed.

lemma sch_pt_add_cancel (x y : sch_point) :
  sch_sub_pt (sch_add_pt x y) y = x.
proof.
rewrite /sch_sub_pt -sch_addA.
rewrite sch_add_pt_oppR.
by rewrite sch_neutralR.
qed.

lemma sch_smul_sub_gen (z t : scalar) :
  sch_sub_pt (sch_smul z sch_generator) (sch_smul t sch_generator) =
  sch_smul (sch_s_sub z t) sch_generator.
proof.
have eqz: sch_s_add (sch_s_sub z t) t = z by rewrite sch_s_sub_def.
have hsmul := sch_smul_add_gen (sch_s_sub z t) t.
rewrite eqz in hsmul.
rewrite hsmul.
by rewrite sch_pt_add_cancel.
qed.

(* Sim announcement z*H - c*P equals (z - c*w)*H at the same generator. *)
lemma sch_sim_announcement_reparam (w c z : scalar) :
  sch_sub_pt (sch_smul z sch_generator) (sch_smul c (sch_pubkey w)) =
  sch_smul (sch_s_sub z (sch_s_mul c w)) sch_generator.
proof.
rewrite /sch_pubkey -sch_smul_mul_embed.
by rewrite sch_smul_sub_gen.
qed.

lemma qssm_pair_eq ['a 'b] (x1 x2 : 'a) (y1 y2 : 'b) :
  x1 = x2 => y1 = y2 => (x1, y1) = (x2, y2).
proof. by move=> -> ->. qed.

lemma qssm_dunit_eq ['a] (x y : 'a) : x = y => dunit x = dunit y.
proof. by move=> ->. qed.
