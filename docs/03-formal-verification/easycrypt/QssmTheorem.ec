require import Real.
require import QssmTypes QssmFS QssmMS QssmLE QssmGames.

theory QssmTheorem.

op Adv_QSSM : distinguisher -> real.

(* Phase 1 assumption placeholders *)
axiom A1_ms_hash_binding :
  forall (D : distinguisher), 0%r <= epsilon_ms_hash_binding.

axiom A2_ms_rom_programmability :
  forall (D : distinguisher), 0%r <= epsilon_ms_rom_programmability.

axiom A4_le_hvzk :
  forall (D : distinguisher), 0%r <= epsilon_le.

(* Explicitly reference MS-3a/MS-3b/MS-3c placeholders from QssmMS *)
axiom use_MS_3a : forall (x : ms_public_input) (s : seed), True.
axiom use_MS_3b : forall (x : ms_public_input), True.
axiom use_MS_3c : forall (x : ms_public_input) (s : seed), True.

(* Main theorem statement skeleton *)
axiom qssm_main_theorem_skeleton :
  forall (D : distinguisher),
    Adv_QSSM D <=
      epsilon_ms_hash_binding +
      epsilon_ms_rom_programmability +
      epsilon_le.

end.
