require import AllCore.

(* Concrete zero-budget model.

   At the current abstraction level every transition that these budgets bound
   is already proved by an exact distribution / statistical-distance equality:

   - MS1 hash-binding: `L_ms1_hash_binding_stage_zero` proves the Real and
     AfterBinding observable distributions are equal.
   - MS2 ROM-programming: `L_ms2_rom_programming_transition_zero` proves the
     AfterBinding and AfterRom observable distributions are equal.
   - LE HVZK: `le_post_rejection_surrogate` and `le_fs_view_surrogate` are the
     identity on the modeled observable, so the LE real and sim view
     distributions coincide and the underlying sdist is identically 0.

   Therefore each budget is defined as `0%r`. This is NOT a nonzero
   cryptographic security bound; it records the exact-zero gap of the current
   model. Any future refinement that introduces a non-identity rejection
   sampler, FS programmer, or quantitative ROM model must restore a nonzero
   budget formula here. *)

op epsilon_ms_hash_binding : real = 0%r.

lemma A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.
proof. by rewrite /epsilon_ms_hash_binding. qed.

op epsilon_ms_rom_programmability : real = 0%r.

lemma A2_ms_rom_programmability_nonneg :
  0%r <= epsilon_ms_rom_programmability.
proof. by rewrite /epsilon_ms_rom_programmability. qed.

op epsilon_le : real = 0%r.

lemma A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.
proof. by rewrite /epsilon_le. qed.