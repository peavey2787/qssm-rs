require import AllCore Distr.
require import Algebra QssmTypes.

(* Uniform scalar source (abstract; ROM / hash_to_scalar instantiates). *)

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
