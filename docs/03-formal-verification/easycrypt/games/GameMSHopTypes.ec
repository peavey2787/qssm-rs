require import AllCore List.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceDistributions SourceTheorem MS LEModel.
require import GameTypes GameViews GameAdvantage.

(* Canonical stage / alignment facts for the MS constructor chain (same x, xms, s). *)
lemma L_ms_MS1_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_real_stage (G_MS_real x xms s) /\
  ms_game_after_binding_stage (G_MS_after_binding x xms s) /\
  ms_game_view_ms_pub (G_MS_real x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_binding x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_real x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_binding x xms s) x s.
proof.
split; first by rewrite /ms_game_real_stage /G_MS_real /G0_real_qssm /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageReal None).
split; first by exact (L_ms_game_after_binding_stage_G x xms s).
split; first by rewrite /G_MS_real /G0_real_qssm;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageReal None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterBinding None).
split; first by rewrite /G_MS_real /G0_real_qssm;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageReal None).
by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterBinding None).
qed.

lemma L_ms_MS2_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_binding_stage (G_MS_after_binding x xms s) /\
  ms_game_after_rom_stage (G_MS_after_rom x xms s) /\
  ms_game_view_ms_pub (G_MS_after_binding x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_rom x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_binding x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s.
proof.
split; first by rewrite /ms_game_after_binding_stage /G_MS_after_binding /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterBinding None).
split; first by rewrite /ms_game_after_rom_stage /G_MS_after_rom /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterBinding None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterBinding None).
by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterRom None).
qed.

lemma L_ms_MS3a_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_rom_stage (G_MS_after_rom x xms s) /\
  ms_game_after_bitness_stage (G_MS_after_bitness x xms s) /\
  ms_game_view_ms_pub (G_MS_after_rom x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s.
proof.
split; first by rewrite /ms_game_after_rom_stage /G_MS_after_rom /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterRom None).
split; first by rewrite /ms_game_after_bitness_stage /G_MS_after_bitness /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterRom None).
by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterBitness None).
qed.

lemma L_ms_MS3b_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_bitness_stage (G_MS_after_bitness x xms s) /\
  ms_game_after_comparison_stage (G_MS_after_comparison x xms s) /\
  ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s.
proof.
split; first by rewrite /ms_game_after_bitness_stage /G_MS_after_bitness /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterBitness None).
split; first by rewrite /ms_game_after_comparison_stage /G_MS_after_comparison /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterComparison None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterComparison None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterBitness None).
by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterComparison None).
qed.

lemma L_ms_MS3c_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_comparison_stage (G_MS_after_comparison x xms s) /\
  ms_game_sim_stage (G_MS_sim x xms s) /\
  ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms /\
  ms_game_view_ms_pub (G_MS_sim x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_sim x xms s) x s.
proof.
split; first by rewrite /ms_game_after_comparison_stage /G_MS_after_comparison /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageAfterComparison None).
split; first by rewrite /ms_game_sim_stage /G_MS_sim /G1_ms_sim_le_real /=;
  exact (L_ms_game_view_stage_mk x s xms witness MSGameStageSim None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageAfterComparison None).
split; first by rewrite /G_MS_sim /G1_ms_sim_le_real;
  exact (L_ms_game_view_ms_pub_mk x s xms witness MSGameStageSim None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageAfterComparison None).
by rewrite /G_MS_sim /G1_ms_sim_le_real;
  exact (L_ms_game_view_qssm_seed_mk x s xms witness MSGameStageSim None).
qed.

(* MS1 canonical hash-binding hop obligation on the concrete stage pair used in
   the G0->G1 telescope. *)
axiom A_MS1_canonical_hash_binding_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms_hash_binding.

(* MS1 generic hash-binding wrapper for compatibility with older src/dst-step
   APIs. Keep as a wrapper-level obligation; canonical proofs should target
   `A_MS1_canonical_hash_binding_bound` first. *)
axiom A_MS1_hash_binding_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    ms1_hash_binding_step src dst xms =>
    Adv src dst D <= epsilon_ms_hash_binding.

(* MS2 canonical ROM/FS hop obligation on the concrete stage pair used in the
   G0->G1 telescope. *)
axiom A_MS2_canonical_rom_programming_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability.

(* MS2 generic ROM/FS wrapper for compatibility with older src/dst-step APIs.
   Keep as a wrapper-level obligation; canonical proofs should target
   `A_MS2_canonical_rom_programming_bound` first. *)
axiom A_MS2_rom_programming_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    ms2_rom_programming_step src dst xms =>
    Adv src dst D <= epsilon_ms_rom_programmability.

(* MS3a canonical bitness exact-simulation obligation on the concrete stage pair
   used in the G0->G1 telescope. *)
axiom A_MS3a_canonical_bitness_exact_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_real_sim_equiv xms s =>
    Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r.

(* MS3a generic step wrapper for compatibility with older src/dst-step APIs.
   Keep as a wrapper-level obligation; canonical proofs should target
   `A_MS3a_canonical_bitness_exact_bound` first. *)
axiom A_MS3a_bitness_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_exact_step src dst xms s =>
    Adv src dst D <= 0%r.

(* MS3b canonical true-clause obligation on the concrete stage pair used in the
   G0->G1 telescope. *)
axiom A_MS3b_canonical_true_clause_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
      ms3b_comparison_operand_bits xms vb tb =>
      ms_highest_differing_bit vb tb p =>
      ms_true_clause_position vb tb p =>
      ms3b_clause_opening_binds xms vb tb p clause_pub r =>
      ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
    Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D <= 0%r.

(* MS3b generic step wrapper for compatibility with older src/dst-step APIs.
   Keep as a wrapper-level obligation; canonical proofs should target
   `A_MS3b_canonical_true_clause_bound` first. *)
axiom A_MS3b_true_clause_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    ms3b_true_clause_exact_step src dst xms =>
    Adv src dst D <= 0%r.

(* MS3c canonical comparison exact-simulation obligation on the concrete stage
   pair used in the G0->G1 telescope. *)
axiom A_MS3c_canonical_comparison_exact_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D <= 0%r.

(* MS3c generic step wrapper for compatibility with older src/dst-step APIs.
   Keep as a wrapper-level obligation; canonical proofs should target
   `A_MS3c_canonical_comparison_exact_bound` first. *)
axiom A_MS3c_comparison_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3c_comparison_exact_step src dst xms s =>
    Adv src dst D <= 0%r.
