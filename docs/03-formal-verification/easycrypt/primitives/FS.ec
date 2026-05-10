require import AllCore List.
require import Domains QssmTypes.
require BudgetParameters.

(* Abstract hash/oracle surfaces (domain tags from Domains.domain_label). *)
op hash_domain : domain_label -> digest list -> digest.
op hash_to_scalar : domain_label -> digest list -> scalar.

(* MS query functions — align with docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md
   section F (Engine B v2 query/challenge path). Labels in code use Domains:
   LABEL_MS_V2_BITNESS_QUERY, LABEL_MS_V2_QUERY_SCALAR (no new label strings here). *)
op ms_bitness_query_digest :
  digest -> int -> digest -> digest -> digest.

(* Comparison programmed query digest: statement digest followed by the ordered
   per-branch announcement digests (Engine B v2 comparison query path). *)
op ms_comparison_query_digest (stmt : digest) (ann_digests : digest list) : digest =
  hash_domain LABEL_MS_V2_COMPARISON_QUERY (stmt :: ann_digests).

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
  domain_label -> domain_label -> bool -> seed -> digest -> digest -> digest -> digest -> digest.

op le_programmed_query_digest :
  domain_label -> digest -> digest -> digest -> digest -> digest -> digest.

(* ROM programmability placeholders *)
op epsilon_ms_hash_binding_semantic : real =
  BudgetParameters.epsilon_ms_hash_binding_semantic.

op epsilon_ms_rom_programmability : real =
  BudgetParameters.epsilon_ms_rom_programmability.

op epsilon_ms_rom_programmability_semantic : real =
  BudgetParameters.epsilon_ms_rom_programmability_semantic.

lemma A1_ms_hash_binding_semantic_nonneg :
  0%r <= epsilon_ms_hash_binding_semantic.
proof. exact BudgetParameters.A1_ms_hash_binding_semantic_nonneg. qed.

(* Primitive ROM-programmability budget assumption on the abstract MS2 error budget. *)
lemma A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.
proof. exact BudgetParameters.A2_ms_rom_programmability_nonneg. qed.

lemma A2_ms_rom_programmability_semantic_nonneg :
  0%r <= epsilon_ms_rom_programmability_semantic.
proof. exact BudgetParameters.A2_ms_rom_programmability_semantic_nonneg. qed.

(* Bitness query digest is a valid ROM query point: `ms_query_to_scalar` is already
   total, so existence follows by choosing its value directly. *)
lemma A2_bitness_programmed_challenge (stmt : digest) (i : int) (d0 d1 : digest) :
  exists (s : scalar),
    ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1) = s.
proof.
exists (ms_query_to_scalar (ms_bitness_query_digest stmt i d0 d1)).
by [].
qed.
