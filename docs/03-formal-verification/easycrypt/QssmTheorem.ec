require import AllCore.
require import QssmTypes QssmFS QssmMS QssmLE QssmGames.

op Adv_QSSM : distinguisher -> real.

(* Phase 1 assumption placeholders *)
axiom A1_ms_hash_binding :
  forall (D : distinguisher), 0%r <= epsilon_ms_hash_binding.

axiom A2_ms_rom_programmability :
  forall (D : distinguisher), 0%r <= epsilon_ms_rom_programmability.

axiom A4_le_hvzk :
  forall (D : distinguisher), 0%r <= epsilon_le.

(* Bridge to MS-3a/b/c placeholders (MS-3a via layered lemma in `QssmMS.ec`) *)
lemma use_MS_3a (x : ms_public_input) (s : seed) : ms3a_bitness_real_sim_equiv x s.
proof.
by apply (MS_3a_exact_bitness_simulation x s).
qed.
axiom use_MS_3b : forall (x : ms_public_input), true.
axiom use_MS_3c : forall (x : ms_public_input) (s : seed), true.

(* Main theorem statement skeleton (not yet derived without game hops) *)
axiom qssm_main_theorem_skeleton :
  forall (D : distinguisher),
    Adv_QSSM D <=
      epsilon_ms_hash_binding +
      epsilon_ms_rom_programmability +
      epsilon_le.
