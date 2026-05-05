require import AllCore.

(* Concrete zero-budget model.

   At the current abstraction level every transition that these budgets bound
   is already proved by an exact distribution / statistical-distance equality:

   - MS1 hash-binding: `L_ms1_hash_binding_stage_zero` proves the Real and
     AfterBinding observable distributions are equal.
   - MS2 ROM-programming: `L_ms2_rom_programming_transition_zero` proves the
     AfterBinding and AfterRom observable distributions are equal.
   - Shadow LE rejection component: `epsilon_le_rej` is installed as the
     future lower rejection budget, but it is intentionally kept at `0%r`
     until the shadow rejection lane is wired into the active LE theorem path.
   - Shadow LE FS component: `epsilon_le_fs` is installed as the future lower
     FS-programming budget, but it is intentionally kept at `0%r` until the
     FS component lane replaces the current compatibility half-budget path in
     the global LE arithmetic.
   - LE HVZK umbrella budget: `epsilon_le` is now defined as the sum of the
     lower component budgets `epsilon_le_rej + epsilon_le_fs`. In the current
     model both component lanes are still exact-zero, so the LE real and sim
     view distributions coincide and the umbrella bound is also identically 0.

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

op epsilon_le_rej : real = 0%r.

lemma A4_le_rejection_nonneg :
  0%r <= epsilon_le_rej.
proof. by rewrite /epsilon_le_rej. qed.

op epsilon_le_fs : real = 0%r.

lemma A4_le_fs_nonneg :
  0%r <= epsilon_le_fs.
proof. by rewrite /epsilon_le_fs. qed.

op epsilon_le : real = epsilon_le_rej + epsilon_le_fs.

lemma epsilon_le_component_sum :
  epsilon_le = epsilon_le_rej + epsilon_le_fs.
proof. by rewrite /epsilon_le. qed.

lemma A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.
proof.
rewrite /epsilon_le /epsilon_le_rej /epsilon_le_fs.
have -> : 0%r + 0%r = 0%r by ring.
by [].
qed.