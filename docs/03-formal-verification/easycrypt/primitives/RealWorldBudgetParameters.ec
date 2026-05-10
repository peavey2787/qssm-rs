require import AllCore Real StdOrder.

(*---*) import RealOrder.

(* Parallel abstract real-world budget owner surface.
   The budgets are projections from an explicit caller-supplied bundle so the
   real-world theorem layer stays axiom-free. *)

type realworld_budget = {
  rwb_epsilon_ms_hash_binding : real;
  rwb_epsilon_ms_rom_programmability : real;
  rwb_epsilon_le_rej : real;
  rwb_epsilon_le_fs : real;
}.

op epsilon_ms_hash_binding_realworld (b : realworld_budget) : real =
  b.`rwb_epsilon_ms_hash_binding.

op epsilon_ms_rom_programmability_realworld (b : realworld_budget) : real =
  b.`rwb_epsilon_ms_rom_programmability.

op epsilon_le_rej_realworld (b : realworld_budget) : real =
  b.`rwb_epsilon_le_rej.

op epsilon_le_fs_realworld (b : realworld_budget) : real =
  b.`rwb_epsilon_le_fs.

op epsilon_le_realworld (b : realworld_budget) : real =
  epsilon_le_rej_realworld b + epsilon_le_fs_realworld b.

op epsilon_top_realworld (b : realworld_budget) : real =
  epsilon_ms_hash_binding_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_le_realworld b.

pred realworld_budget_nonnegative (b : realworld_budget) =
  0%r <= epsilon_ms_hash_binding_realworld b /\
  0%r <= epsilon_ms_rom_programmability_realworld b /\
  0%r <= epsilon_le_rej_realworld b /\
  0%r <= epsilon_le_fs_realworld b.

lemma epsilon_le_realworld_component_sum (b : realworld_budget) :
  epsilon_le_realworld b =
  epsilon_le_rej_realworld b + epsilon_le_fs_realworld b.
proof. by rewrite /epsilon_le_realworld. qed.

lemma epsilon_top_realworld_component_sum (b : realworld_budget) :
  epsilon_top_realworld b =
  epsilon_ms_hash_binding_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_ms_rom_programmability_realworld b +
  epsilon_le_realworld b.
proof. by rewrite /epsilon_top_realworld. qed.

lemma realworld_budget_nonnegative_ms_hash_binding (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_ms_hash_binding_realworld b.
proof.
move=> Hnonneg.
rewrite /realworld_budget_nonnegative in Hnonneg.
by case: Hnonneg.
qed.

lemma realworld_budget_nonnegative_ms_rom_programmability (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_ms_rom_programmability_realworld b.
proof.
move=> Hnonneg.
rewrite /realworld_budget_nonnegative in Hnonneg.
by case: Hnonneg => _ [Hms2 _].
qed.

lemma realworld_budget_nonnegative_le_rej (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_le_rej_realworld b.
proof.
move=> Hnonneg.
rewrite /realworld_budget_nonnegative in Hnonneg.
by case: Hnonneg => _ [_ [Hlej _]].
qed.

lemma realworld_budget_nonnegative_le_fs (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_le_fs_realworld b.
proof.
move=> Hnonneg.
rewrite /realworld_budget_nonnegative in Hnonneg.
by case: Hnonneg => _ [_ [_ Hlefs]].
qed.

lemma epsilon_le_realworld_nonneg (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_le_realworld b.
proof.
move=> Hnonneg.
have Hlej := realworld_budget_nonnegative_le_rej b Hnonneg.
have Hlefs := realworld_budget_nonnegative_le_fs b Hnonneg.
rewrite /epsilon_le_realworld.
by smt().
qed.

lemma epsilon_top_realworld_nonneg (b : realworld_budget) :
  realworld_budget_nonnegative b =>
  0%r <= epsilon_top_realworld b.
proof.
move=> Hnonneg.
have Hms1 := realworld_budget_nonnegative_ms_hash_binding b Hnonneg.
have Hms2 := realworld_budget_nonnegative_ms_rom_programmability b Hnonneg.
have Hle := epsilon_le_realworld_nonneg b Hnonneg.
rewrite /epsilon_top_realworld.
by smt().
qed.