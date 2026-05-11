require import AllCore Distr.
require import Algebra QssmTypes ScalarSampler.

(* Uniform scalar source (abstract; ROM / hash_to_scalar instantiates). *)

op duni_scalar : scalar distr = canonical_scalar_sampler.

lemma duni_scalar_lossless :
  is_lossless duni_scalar.
proof. exact scalar_sampler_lossless. qed.

lemma duni_scalar_invariant_add (t : scalar) :
  dlet duni_scalar (fun alpha => dunit (sch_s_add alpha t)) = duni_scalar.
proof.
rewrite /duni_scalar /sch_s_add /scalar_sampler_translate.
exact (scalar_sampler_translation_invariant t).
qed.

lemma sch_smul_sub_add_gen (x y : scalar) :
  sch_smul (sch_s_sub (sch_s_add x y) y) sch_generator =
  sch_smul x sch_generator.
proof.
rewrite -(sch_smul_sub_gen (sch_s_add x y) y) sch_smul_add_gen.
exact (sch_pt_add_cancel (sch_smul x sch_generator)
        (sch_smul y sch_generator)).
qed.

(* Uniform-shift reparameterization at pair level (finite-field standard fact):
   alpha <- U; output (alpha*H, alpha+t)  ==  z <- U; output ((z-t)*H, z). *)
lemma duni_scalar_shift_reparam (t : scalar) :
  dlet duni_scalar (fun alpha =>
    dunit ((sch_smul alpha sch_generator), (sch_s_add alpha t))) =
  dlet duni_scalar (fun z =>
    dunit ((sch_smul (sch_s_sub z t) sch_generator), z)).
proof.
pose G (z : scalar) :=
  dunit ((sch_smul (sch_s_sub z t) sch_generator), z).
have Hpoint :
  dlet duni_scalar (fun alpha =>
    dlet (dunit (sch_s_add alpha t)) G) =
  dlet duni_scalar (fun alpha =>
    dunit ((sch_smul alpha sch_generator), (sch_s_add alpha t))).
  apply in_eq_dlet=> alpha _.
  have Hunit :
    dlet (dunit (sch_s_add alpha t)) G =
    dunit ((sch_smul (sch_s_sub (sch_s_add alpha t) t) sch_generator),
      (sch_s_add alpha t)).
    by rewrite (dlet_unit G (sch_s_add alpha t)) /G.
  have Hpair :
    dunit ((sch_smul (sch_s_sub (sch_s_add alpha t) t) sch_generator),
      (sch_s_add alpha t)) =
    dunit ((sch_smul alpha sch_generator), (sch_s_add alpha t)).
    apply (qssm_dunit_eq
    ((sch_smul (sch_s_sub (sch_s_add alpha t) t) sch_generator),
      (sch_s_add alpha t))
    ((sch_smul alpha sch_generator), (sch_s_add alpha t))).
    apply (qssm_pair_eq
      (sch_smul (sch_s_sub (sch_s_add alpha t) t) sch_generator)
      (sch_smul alpha sch_generator)
      (sch_s_add alpha t)
      (sch_s_add alpha t)).
    - by rewrite sch_smul_sub_add_gen.
    - by [].
  by smt().
rewrite -Hpoint -dlet_dlet duni_scalar_invariant_add /G.
by [].
qed.

(* Single-bit observable: announcement point * FS response scalar.
   Branch pairs keep internal randomness (alpha or z) next to (A,z). *)

type schnorr_single_bit_obsv = sch_point * scalar.

type schnorr_single_bit_real_branch = scalar * schnorr_single_bit_obsv.

type schnorr_single_bit_sim_branch = scalar * schnorr_single_bit_obsv.

op schnorr_obsv_of_real (b : schnorr_single_bit_real_branch) : schnorr_single_bit_obsv =
  snd b.

op schnorr_obsv_of_sim (b : schnorr_single_bit_sim_branch) : schnorr_single_bit_obsv =
  snd b.

(* Observable distributions on `schnorr_single_bit_obsv distr` *)

op d_ms3a_schnorr_real (w c : scalar) : schnorr_single_bit_obsv distr =
  dlet duni_scalar (fun alpha =>
    dunit ((sch_smul alpha sch_generator),
           (sch_s_add alpha (sch_s_mul c w)))).

op d_ms3a_schnorr_sim (w c : scalar) : schnorr_single_bit_obsv distr =
  dlet duni_scalar (fun z =>
    dunit ((sch_sub_pt (sch_smul z sch_generator)
              (sch_smul c (sch_pubkey w))),
           z)).

(* Pointwise bridge after `duni_scalar_shift_reparam` (algebra only). *)
lemma ms3a_schnorr_reparam_obs_eq (w c z : scalar) :
  (sch_smul (sch_s_sub z (sch_s_mul c w)) sch_generator, z) =
  (sch_sub_pt (sch_smul z sch_generator) (sch_smul c (sch_pubkey w)), z).
proof.
apply (qssm_pair_eq (sch_smul (sch_s_sub z (sch_s_mul c w)) sch_generator)
                    (sch_sub_pt (sch_smul z sch_generator) (sch_smul c (sch_pubkey w)))
                    z z).
by rewrite -(sch_sim_announcement_reparam w c z).
by [].
qed.

(* Joint law from uniform-shift reparam + announcement algebra bridge. *)
lemma MS_3a_single_branch_schnorr_reparam (w c : scalar) :
  d_ms3a_schnorr_real w c = d_ms3a_schnorr_sim w c.
proof.
rewrite /d_ms3a_schnorr_real /d_ms3a_schnorr_sim.
rewrite (duni_scalar_shift_reparam (sch_s_mul c w)).
apply in_eq_dlet=> z _.
exact (qssm_dunit_eq _ _ (ms3a_schnorr_reparam_obs_eq w c z)).
qed.
