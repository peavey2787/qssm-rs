require import AllCore Real StdOrder.

(*---*) import RealOrder.

require import SourceTypes.
require import ComparisonPayloadSemanticBridge.
require import ComparisonPayloadSemanticLiveParameterizedCore.

(* Parallel reduction-facing MS2 surface.
   This exposes the parameterized public-observable divergence carrier used by
   the duplicated MS2 landing without asserting that the frozen toy live mass
   is negligible. *)

op ms2_concrete_reduction_advantage (xms : ms_public_input) : real.

pred ms2_concrete_reduction_obligation
  (epsilon_ms2_bound : real) (xms : ms_public_input) =
  mu (d_ms_rom_semantic_coupled_state_parameterized xms)
    (ms_rom_public_observable_divergence_condition xms) <=
      ms2_concrete_reduction_advantage xms /\
  ms2_concrete_reduction_advantage xms <= epsilon_ms2_bound.

lemma A_MS2_concrete_reduction_bound_from_obligation
  (epsilon_ms2_bound : real) (xms : ms_public_input) :
  ms2_concrete_reduction_obligation epsilon_ms2_bound xms =>
  mu (d_ms_rom_semantic_coupled_state_parameterized xms)
    (ms_rom_public_observable_divergence_condition xms) <=
    epsilon_ms2_bound.
proof.
move=> Hobl.
case: Hobl => Hmass Hbound.
by apply (ler_trans _ _ _ Hmass Hbound).
qed.