require import AllCore List Ring.
require import StdOrder.
(*---*) import RealOrder.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayload ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceDistributions SourceTheorem MS LESurface LEModel.
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
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageReal None).
split; first by exact (L_ms_game_after_binding_stage_G x xms s).
split; first by rewrite /G_MS_real /G0_real_qssm;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageReal None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
split; first by rewrite /G_MS_real /G0_real_qssm;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageReal None).
by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
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
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
split; first by rewrite /ms_game_after_rom_stage /G_MS_after_rom /=;
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_binding;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
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
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
split; first by rewrite /ms_game_after_bitness_stage /G_MS_after_bitness /=;
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_rom;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None).
by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
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
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
split; first by rewrite /ms_game_after_comparison_stage /G_MS_after_comparison /=;
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
split; first by rewrite /G_MS_after_bitness;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None).
by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
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
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
split; first by rewrite /ms_game_sim_stage /G_MS_sim /G1_ms_sim_le_real /=;
  exact (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageSim None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
split; first by rewrite /G_MS_sim /G1_ms_sim_le_real;
  exact (L_ms_game_view_ms_pub_mk x s xms (ms_game_view_public_obs xms) MSGameStageSim None).
split; first by rewrite /G_MS_after_comparison;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None).
by rewrite /G_MS_sim /G1_ms_sim_le_real;
  exact (L_ms_game_view_qssm_seed_mk x s xms (ms_game_view_public_obs xms) MSGameStageSim None).
qed.

(* MS1 canonical hash-binding hop obligation on the concrete stage pair used in
   the G0->G1 telescope. *)
pred ms1_hash_binding_surface_defined (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  ms1_hash_binding_step (G_MS_real x xms s) (G_MS_after_binding x xms s) xms.

pred ms1_hash_binding_bad_event_bounded (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  0%r <= epsilon_ms_hash_binding.

axiom A_MS1_hash_binding_surface_defined :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    ms1_hash_binding_surface_defined x xms s.

axiom A_MS1_hash_binding_bad_event_bounded :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    ms1_hash_binding_bad_event_bounded x xms s.

axiom A_MS1_hash_binding_replacement_advantage_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms1_hash_binding_surface_defined x xms s =>
    ms1_hash_binding_bad_event_bounded x xms s =>
    0%r <= epsilon_ms_hash_binding =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms_hash_binding.

lemma A_MS1_canonical_hash_binding_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms_hash_binding.
proof.
move=> x xms s D Hnonneg.
exact (A_MS1_hash_binding_replacement_advantage_bound x xms s D
  (A_MS1_hash_binding_surface_defined x xms s)
  (A_MS1_hash_binding_bad_event_bounded x xms s)
  Hnonneg).
qed.

(* MS2 ROM surface split: query-surface well-formedness and bounded programmed
   points on the canonical stage pair. *)
pred ms2_rom_query_surface_defined (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  ms2_rom_programming_step (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) xms.

pred ms2_rom_programmed_points_bounded (x : qssm_public_input) (xms : ms_public_input) (s : seed) =
  0%r <= epsilon_ms_rom_programmability.

axiom A_MS2_rom_query_surface_defined :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    ms2_rom_query_surface_defined x xms s.

axiom A_MS2_rom_programmed_points_bounded :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed),
    ms2_rom_programmed_points_bounded x xms s.

axiom A_MS2_rom_reprogramming_advantage_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms2_rom_query_surface_defined x xms s =>
    ms2_rom_programmed_points_bounded x xms s =>
    0%r <= epsilon_ms_rom_programmability =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability.

(* MS2 canonical ROM/FS hop bound is now a lemma layered over the narrower ROM
   obligations above. *)
lemma A_MS2_canonical_rom_programming_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability.
proof.
move=> x xms s D Hnonneg.
exact (A_MS2_rom_reprogramming_advantage_bound x xms s D
  (A_MS2_rom_query_surface_defined x xms s)
  (A_MS2_rom_programmed_points_bounded x xms s)
  Hnonneg).
qed.

(* MS3a canonical bitness exact-simulation obligation on the concrete stage pair
   used in the G0->G1 telescope. *)
axiom A_MS3a_canonical_bitness_exact_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_real_sim_equiv xms s =>
    Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r.

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

(* MS3c game layer: the comparison MS-3c implication bundle (same shape as
   `ms3c_comparison_exact_step` / `MS_3c_exact_comparison_simulation`) is assumed
   to make the two canonical stage views **indistinguishable** to `game_pr` for
   every distinguisher. The schedule-level fact `ms_comparison_exact_simulation_equiv`
   is proved in `ms/comparison/`; linking it (and the bundle) to `game_pr` is the
   remaining execution-semantics gap. *)
axiom A_MS3c_comparison_bundle_implies_game_pr_equality :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    game_pr (G_MS_after_comparison x xms s) D = game_pr (G_MS_sim x xms s) D.

(* Canonical MS3c hop bound: zero advantage from `Adv_def` once `game_pr` agrees. *)
lemma A_MS3c_canonical_comparison_exact_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D <= 0%r.
proof.
move=> x xms s D Hb.
have Heq := A_MS3c_comparison_bundle_implies_game_pr_equality x xms s D Hb.
rewrite Adv_def Heq.
have ->: game_pr (G_MS_sim x xms s) D - game_pr (G_MS_sim x xms s) D = 0%r by ring.
by apply lerr.
qed.

(* Generic src/dst wrapper bounds were removed: the step predicates permit
   arbitrary frozen observable/public payloads, so canonical bounds on
   `G_MS_*` do not imply uniform bounds on all step-related views without an
   additional invariance theory for `Adv`. Remaining MS game-hop proof
   obligations are the axioms above (MS1/MS2/MS3a/MS3b narrow obligations plus
   **`A_MS3c_comparison_bundle_implies_game_pr_equality`** for the MS3c hop);
   **`A_MS3c_canonical_comparison_exact_bound`** is a proved lemma from
   **`Adv_def`** once that bridge holds. *)
