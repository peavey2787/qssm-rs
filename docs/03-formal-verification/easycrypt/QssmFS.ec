require import Real.
require import QssmDomains QssmTypes.

theory QssmFS.

(* Abstract hash/oracle surfaces *)
op hash_domain : string -> digest list -> digest.
op hash_to_scalar : string -> digest list -> scalar.

(* MS query functions (execution-spec abstraction level) *)
op ms_bitness_query_digest :
  digest -> int -> digest -> digest -> digest.

op ms_comparison_query_digest :
  digest -> digest list -> digest.

op ms_query_to_scalar :
  digest -> scalar.

(* LE challenge/query digest functions *)
op le_challenge_seed :
  string -> string -> bool -> seed -> digest -> digest -> digest -> digest -> digest.

op le_programmed_query_digest :
  string -> digest -> digest -> digest -> digest -> digest -> digest.

(* ROM programmability placeholders *)
op epsilon_ms_rom_programmability : real.

axiom A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.

axiom A2_programmable_oracle_exists :
  forall (q : digest), exists (s : scalar), ms_query_to_scalar q = s.

end.
