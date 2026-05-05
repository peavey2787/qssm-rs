require import AllCore.

(* External model-budget boundary.

   These budgets remain abstract parameters of the EasyCrypt model. This file
   centralizes their declarations and the accompanying nonnegativity
   assumptions so the boundary is explicit and shared, without pretending the
   parameters were derived internally. *)

op epsilon_ms_hash_binding : real.

axiom A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.

op epsilon_ms_rom_programmability : real.

axiom A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.

op epsilon_le : real.

axiom A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.