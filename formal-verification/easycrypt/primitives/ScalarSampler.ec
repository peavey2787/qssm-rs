require import AllCore Distr.
require import ScalarOwner QssmTypes.

(* Future owner for the scalar-sampling boundary.

   This file deliberately introduces only the owner surface: a canonical scalar
   sampler together with the theorem targets it must eventually prove. The live
   Schnorr/MS theories still use `duni_scalar` in `ms/SchnorrBranch.ec` until
   this owner can supply the needed laws constructively. *)

op canonical_scalar_sampler : scalar distr = ScalarOwner.scalar_uniform.

op scalar_sampler_translate (alpha t : scalar) : scalar =
  SchScalarRing.( + ) alpha t.

lemma scalar_sampler_lossless :
  is_lossless canonical_scalar_sampler.
proof. exact ScalarOwner.scalar_uniform_lossless. qed.

lemma scalar_sampler_translation_invariant (t : scalar) :
  dlet canonical_scalar_sampler
    (fun alpha => dunit (scalar_sampler_translate alpha t)) =
  canonical_scalar_sampler.
proof. exact (ScalarOwner.scalar_uniform_invariant_add t). qed.