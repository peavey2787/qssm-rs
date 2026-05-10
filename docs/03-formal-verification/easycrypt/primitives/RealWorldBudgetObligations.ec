require import AllCore Real StdOrder.
require import RealWorldBudgetParameters.

(*---*) import RealOrder.

(* Generic real-world budget obligations. The lower layers instantiate these
   predicates with concrete live failure masses, but this file stays purely
   arithmetic so it can compile before any routed proof surface. *)

pred le_realworld_obligations
  (b : realworld_budget) (epsilon_le_rej_actual epsilon_le_fs_actual : real) =
  epsilon_le_rej_actual <= epsilon_le_rej_realworld b /\
  epsilon_le_fs_actual <= epsilon_le_fs_realworld b.

pred ms_realworld_obligations
  (b : realworld_budget)
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) =
  epsilon_ms_hash_binding_actual <= epsilon_ms_hash_binding_realworld b /\
  epsilon_ms_rom_actual <= epsilon_ms_rom_programmability_realworld b.

pred qssm_realworld_obligations
  (b : realworld_budget)
  (epsilon_le_rej_actual epsilon_le_fs_actual
   epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) =
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual /\
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual.

lemma le_realworld_obligations_rejection_bound
  (b : realworld_budget) (epsilon_le_rej_actual epsilon_le_fs_actual : real) :
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual =>
  epsilon_le_rej_actual <= epsilon_le_rej_realworld b.
proof.
move=> H.
by case: H.
qed.

lemma le_realworld_obligations_fs_bound
  (b : realworld_budget) (epsilon_le_rej_actual epsilon_le_fs_actual : real) :
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual =>
  epsilon_le_fs_actual <= epsilon_le_fs_realworld b.
proof.
move=> H.
by case: H.
qed.

lemma ms_realworld_obligations_ms1_bound
  (b : realworld_budget)
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  epsilon_ms_hash_binding_actual <= epsilon_ms_hash_binding_realworld b.
proof.
move=> H.
by case: H.
qed.

lemma ms_realworld_obligations_ms2_bound
  (b : realworld_budget)
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  epsilon_ms_rom_actual <= epsilon_ms_rom_programmability_realworld b.
proof.
move=> H.
by case: H.
qed.

lemma qssm_realworld_obligations_le
  (b : realworld_budget)
  (epsilon_le_rej_actual epsilon_le_fs_actual
   epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  qssm_realworld_obligations b
    epsilon_le_rej_actual epsilon_le_fs_actual
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual.
proof.
move=> H.
by case: H.
qed.

lemma qssm_realworld_obligations_ms
  (b : realworld_budget)
  (epsilon_le_rej_actual epsilon_le_fs_actual
   epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  qssm_realworld_obligations b
    epsilon_le_rej_actual epsilon_le_fs_actual
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual.
proof.
move=> H.
by case: H.
qed.

lemma le_realworld_obligations_rejection_budget_nonneg
  (b : realworld_budget) (epsilon_le_rej_actual epsilon_le_fs_actual : real) :
  0%r <= epsilon_le_rej_actual =>
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual =>
  0%r <= epsilon_le_rej_realworld b.
proof.
move=> Hactual H.
have Hbudget := le_realworld_obligations_rejection_bound b
  epsilon_le_rej_actual epsilon_le_fs_actual H.
by smt().
qed.

lemma le_realworld_obligations_fs_budget_nonneg
  (b : realworld_budget) (epsilon_le_rej_actual epsilon_le_fs_actual : real) :
  0%r <= epsilon_le_fs_actual =>
  le_realworld_obligations b epsilon_le_rej_actual epsilon_le_fs_actual =>
  0%r <= epsilon_le_fs_realworld b.
proof.
move=> Hactual H.
have Hbudget := le_realworld_obligations_fs_bound b
  epsilon_le_rej_actual epsilon_le_fs_actual H.
by smt().
qed.

lemma ms_realworld_obligations_ms1_budget_nonneg
  (b : realworld_budget)
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  0%r <= epsilon_ms_hash_binding_actual =>
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  0%r <= epsilon_ms_hash_binding_realworld b.
proof.
move=> Hactual H.
have Hbudget := ms_realworld_obligations_ms1_bound b
  epsilon_ms_hash_binding_actual epsilon_ms_rom_actual H.
by smt().
qed.

lemma ms_realworld_obligations_ms2_budget_nonneg
  (b : realworld_budget)
  (epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  0%r <= epsilon_ms_rom_actual =>
  ms_realworld_obligations b epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  0%r <= epsilon_ms_rom_programmability_realworld b.
proof.
move=> Hactual H.
have Hbudget := ms_realworld_obligations_ms2_bound b
  epsilon_ms_hash_binding_actual epsilon_ms_rom_actual H.
by smt().
qed.

lemma qssm_realworld_obligations_budget_nonnegative
  (b : realworld_budget)
  (epsilon_le_rej_actual epsilon_le_fs_actual
   epsilon_ms_hash_binding_actual epsilon_ms_rom_actual : real) :
  0%r <= epsilon_le_rej_actual =>
  0%r <= epsilon_le_fs_actual =>
  0%r <= epsilon_ms_hash_binding_actual =>
  0%r <= epsilon_ms_rom_actual =>
  qssm_realworld_obligations b
    epsilon_le_rej_actual epsilon_le_fs_actual
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual =>
  realworld_budget_nonnegative b.
proof.
move=> Hlej_actual Hlefs_actual Hms1_actual Hms2_actual Hqssm.
have Hle := qssm_realworld_obligations_le b
  epsilon_le_rej_actual epsilon_le_fs_actual
  epsilon_ms_hash_binding_actual epsilon_ms_rom_actual Hqssm.
have Hms := qssm_realworld_obligations_ms b
  epsilon_le_rej_actual epsilon_le_fs_actual
  epsilon_ms_hash_binding_actual epsilon_ms_rom_actual Hqssm.
rewrite /realworld_budget_nonnegative.
split.
  exact (ms_realworld_obligations_ms1_budget_nonneg b
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual Hms1_actual Hms).
split.
  exact (ms_realworld_obligations_ms2_budget_nonneg b
    epsilon_ms_hash_binding_actual epsilon_ms_rom_actual Hms2_actual Hms).
split.
  exact (le_realworld_obligations_rejection_budget_nonneg b
    epsilon_le_rej_actual epsilon_le_fs_actual Hlej_actual Hle).
exact (le_realworld_obligations_fs_budget_nonneg b
  epsilon_le_rej_actual epsilon_le_fs_actual Hlefs_actual Hle).
qed.