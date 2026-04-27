require import Real.
require import QssmTypes QssmFS.

theory QssmMS.

(* MS v2 transcript observable surface (abstract, aligned to execution spec) *)
op ms_statement_digest : ms_transcript_observable -> digest.
op ms_result_bit : ms_transcript_observable -> bool.
op ms_bitness_global_challenges : ms_transcript_observable -> digest list.
op ms_comparison_global_challenge : ms_transcript_observable -> digest.
op ms_transcript_digest : ms_transcript_observable -> digest.

(* Simulator/prover abstraction *)
op ms_real_transcript : ms_public_input -> game_view.
op ms_sim_transcript : ms_public_input -> seed -> game_view.

op epsilon_ms_hash_binding : real.

axiom A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.

(* MS-3a/MS-3b/MS-3c placeholders: admitted/axiomatized in Phase 1 *)
axiom MS_3a_exact_bitness_simulation :
  forall (x : ms_public_input) (s : seed), True.

axiom MS_3b_true_clause_characterization :
  forall (x : ms_public_input), True.

axiom MS_3c_exact_comparison_simulation :
  forall (x : ms_public_input) (s : seed), True.

end.
