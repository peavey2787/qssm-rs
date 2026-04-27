require import AllCore Distr.
require import QssmTypes.

(* ========================================================================== *)
(* QssmSchnorrSingleBit — single-branch Schnorr reparameterization (MS-3a). *)
(*                                                                            *)
(* A) Permanent algebra model (abstract scalar / point group + homomorphism   *)
(*    on the fixed generator).                                                *)
(* B) Uniformity on scalars: abstract `duni_scalar` + translation invariance. *)
(* D) Temporary: one uniform-shift reparam axiom for dlet/joint law.          *)
(* ========================================================================== *)

(* -------------------------------------------------------------------------- *)
(* (A) One-generator carrier: points + scalars (abstract, curve-agnostic).   *)
(* -------------------------------------------------------------------------- *)

type sch_point.

op sch_generator : sch_point.
op sch_neutral_pt : sch_point.
op sch_opp_pt : sch_point -> sch_point.
op sch_add_pt : sch_point -> sch_point -> sch_point.

op sch_sub_pt (x y : sch_point) : sch_point =
  sch_add_pt x (sch_opp_pt y).

op sch_smul : scalar -> sch_point -> sch_point.

op sch_s_add : scalar -> scalar -> scalar.
op sch_s_sub : scalar -> scalar -> scalar.
op sch_s_mul : scalar -> scalar -> scalar.

(* P = w * H *)
op sch_pubkey (w : scalar) : sch_point = sch_smul w sch_generator.

(* --- (A) Scalar group fragment (needed for Schnorr algebra on exponents) --- *)

axiom sch_s_addA (x y z : scalar) :
  sch_s_add x (sch_s_add y z) = sch_s_add (sch_s_add x y) z.

axiom sch_s_addC (x y : scalar) :
  sch_s_add x y = sch_s_add y x.

axiom sch_s_sub_def (x y : scalar) :
  sch_s_add (sch_s_sub x y) y = x.

axiom sch_s_mul_add_distr (c w1 w2 : scalar) :
  sch_s_mul c (sch_s_add w1 w2) = sch_s_add (sch_s_mul c w1) (sch_s_mul c w2).

(* --- (A) Point group fragment + homomorphism at H --- *)

axiom sch_addA (x y z : sch_point) :
  sch_add_pt x (sch_add_pt y z) = sch_add_pt (sch_add_pt x y) z.

axiom sch_addC (x y : sch_point) :
  sch_add_pt x y = sch_add_pt y x.

axiom sch_neutralL (x : sch_point) :
  sch_add_pt sch_neutral_pt x = x.

axiom sch_oppL (x : sch_point) :
  sch_add_pt (sch_opp_pt x) x = sch_neutral_pt.

axiom sch_smul_add_gen (s t : scalar) :
  sch_smul (sch_s_add s t) sch_generator =
  sch_add_pt (sch_smul s sch_generator) (sch_smul t sch_generator).

axiom sch_smul_mul_embed (c w : scalar) :
  sch_smul (sch_s_mul c w) sch_generator =
  sch_smul c (sch_smul w sch_generator).

(* sch_neutralR was redundant given sch_addC + sch_neutralL. *)
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
rewrite /sch_sub_pt sch_addA.
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

(* -------------------------------------------------------------------------- *)
(* (B) Uniform scalar source (abstract; ROM / hash_to_scalar instantiates).  *)
(* -------------------------------------------------------------------------- *)

op duni_scalar : scalar distr.

axiom duni_scalar_invariant_add (t : scalar) :
  dlet duni_scalar (fun alpha => dunit (sch_s_add alpha t)) = duni_scalar.

(* Uniform-shift reparameterization at pair level (finite-field standard fact):
   alpha <- U; output (alpha*H, alpha+t)  ==  z <- U; output ((z-t)*H, z). *)
axiom duni_scalar_shift_reparam (t : scalar) :
  dlet duni_scalar (fun alpha =>
    dunit ((sch_smul alpha sch_generator), (sch_s_add alpha t))) =
  dlet duni_scalar (fun z =>
    dunit ((sch_smul (sch_s_sub z t) sch_generator), z)).

(* -------------------------------------------------------------------------- *)
(* Single-bit observable: announcement point * FS response scalar.            *)
(* Branch pairs keep internal randomness (alpha or z) next to (A,z).        *)
(* -------------------------------------------------------------------------- *)

type schnorr_single_bit_obsv = sch_point * scalar.

type schnorr_single_bit_real_branch = scalar * schnorr_single_bit_obsv.

type schnorr_single_bit_sim_branch = scalar * schnorr_single_bit_obsv.

op schnorr_obsv_of_real (b : schnorr_single_bit_real_branch) : schnorr_single_bit_obsv =
  snd b.

op schnorr_obsv_of_sim (b : schnorr_single_bit_sim_branch) : schnorr_single_bit_obsv =
  snd b.

(* -------------------------------------------------------------------------- *)
(* Observable distributions on `schnorr_single_bit_obsv distr`              *)
(*                                                                            *)
(* Real (one genuine Schnorr branch, fixed witness w and FS challenge c):   *)
(*   sample alpha <- duni_scalar;                                             *)
(*   output (a, z) with a = alpha*H, z = alpha + c*w.                         *)
(*                                                                            *)
(* Simulated (same observables, scripted FS side):                            *)
(*   sample z <- duni_scalar;                                                 *)
(*   output (a, z) with a = z*H - c*(w*H), z unchanged.                       *)
(*                                                                            *)
(* Claim MS_3a_single_branch_schnorr_reparam: these two distributions on     *)
(* `schnorr_single_bit_obsv` are **equal** (not merely indistinguishable).   *)
(* -------------------------------------------------------------------------- *)

op d_ms3a_schnorr_real (w c : scalar) : schnorr_single_bit_obsv distr =
  dlet duni_scalar (fun alpha =>
    dunit ((sch_smul alpha sch_generator),
           (sch_s_add alpha (sch_s_mul c w)))).

op d_ms3a_schnorr_sim (w c : scalar) : schnorr_single_bit_obsv distr =
  dlet duni_scalar (fun z =>
    dunit ((sch_sub_pt (sch_smul z sch_generator)
              (sch_smul c (sch_pubkey w))),
           z)).

(* (D) Joint law from uniform-shift reparam + announcement algebra bridge. *)
lemma MS_3a_single_branch_schnorr_reparam (w c : scalar) :
  d_ms3a_schnorr_real w c = d_ms3a_schnorr_sim w c.
proof.
rewrite /d_ms3a_schnorr_real /d_ms3a_schnorr_sim.
have Hshift := duni_scalar_shift_reparam (sch_s_mul c w).
rewrite Hshift.
apply in_eq_dlet => z _.
rewrite -(sch_sim_announcement_reparam w c z).
by [].
qed.
