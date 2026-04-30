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
by smt().
qed.

lemma L_ms_MS2_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_binding_stage (G_MS_after_binding x xms s) /\
  ms_game_after_rom_stage (G_MS_after_rom x xms s) /\
  ms_game_view_ms_pub (G_MS_after_binding x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_rom x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_binding x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s.
proof.
by smt().
qed.

lemma L_ms_MS3a_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_rom_stage (G_MS_after_rom x xms s) /\
  ms_game_after_bitness_stage (G_MS_after_bitness x xms s) /\
  ms_game_view_ms_pub (G_MS_after_rom x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s.
proof.
by smt().
qed.

lemma L_ms_MS3b_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_bitness_stage (G_MS_after_bitness x xms s) /\
  ms_game_after_comparison_stage (G_MS_after_comparison x xms s) /\
  ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms /\
  ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s.
proof.
by smt().
qed.

lemma L_ms_MS3c_stage_premises (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_comparison_stage (G_MS_after_comparison x xms s) /\
  ms_game_sim_stage (G_MS_sim x xms s) /\
  ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms /\
  ms_game_view_ms_pub (G_MS_sim x xms s) xms /\
  ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s /\
  ms_game_view_qssm_seed (G_MS_sim x xms s) x s.
proof.
by smt().
qed.

(* MS1: narrow hash-binding replacement hop (frozen MS observable boundary). *)
axiom A_MS1_hash_binding_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    ms1_hash_binding_step src dst xms =>
    Adv src dst D <= epsilon_ms_hash_binding.

(* MS2: narrow ROM/FS programming hop (frozen MS observable boundary). *)
axiom A_MS2_rom_programming_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    ms2_rom_programming_step src dst xms =>
    Adv src dst D <= epsilon_ms_rom_programmability.

(* MS3a: bitness exact-simulation hop (ROM -> bitness stage; `ms3a_bitness_real_sim_equiv` in predicate). *)
axiom A_MS3a_bitness_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_exact_step src dst xms s =>
    Adv src dst D <= 0%r.

(* MS3b: true-clause hop (bitness -> comparison stage; MS-3b forall bundle in predicate). *)
axiom A_MS3b_true_clause_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    ms3b_true_clause_exact_step src dst xms =>
    Adv src dst D <= 0%r.

(* MS3c: comparison hop (comparison -> sim stage; MS-3c implication bundle in predicate). *)
axiom A_MS3c_comparison_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3c_comparison_exact_step src dst xms s =>
    Adv src dst D <= 0%r.
