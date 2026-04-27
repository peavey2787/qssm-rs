require import AllCore List.
require import QssmDomains QssmTypes.

(* Abstract hash/oracle surfaces *)
op hash_domain : string -> digest list -> digest.
op hash_to_scalar : string -> digest list -> scalar.

(* MS query functions — align with docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md
   section F (Engine B v2 query/challenge path). Labels in code use QssmDomains:
   LABEL_MS_V2_BITNESS_QUERY, LABEL_MS_V2_QUERY_SCALAR (no new label strings here). *)
op ms_bitness_query_digest :
  digest -> int -> digest -> digest -> digest.

op ms_comparison_query_digest :
  digest -> digest list -> digest.

op ms_query_to_scalar :
  digest -> scalar.

(* Fiat–Shamir scalar for one bitness query digest (hash_to_scalar path abstracted). *)
op ms_bitness_fs_scalar (stmt : digest) (i : int) (d0 d1 : digest) : scalar =
  ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1).

(* Global FS challenge equals ROM output at the announcement-only bitness digest. *)
pred ms_bitness_fs_programmed (stmt : digest) (i : int) (d0 d1 : digest) (cglob : scalar) =
  cglob = ms_bitness_fs_scalar stmt i d0 d1.

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

(* Bitness query digest is a valid ROM query point: some scalar response exists.
   Corollary of A2_programmable_oracle_exists (not a new cryptographic axiom). *)
lemma A2_bitness_programmed_challenge (stmt : digest) (i : int) (d0 d1 : digest) :
  exists (s : scalar),
    ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1) = s.
proof.
exact (A2_programmable_oracle_exists (ms_bitness_query_digest stmt i d0 d1)).
qed.
