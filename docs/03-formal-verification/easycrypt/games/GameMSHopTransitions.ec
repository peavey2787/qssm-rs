require import AllCore List.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceDistributions SourceTheorem MS LESurface LEModel.
require import GameTypes GameViews GameAdvantage GameMSHopTypes.

lemma L_ms1_hash_binding_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms1_hash_binding_step (G_MS_real x xms s) (G_MS_after_binding x xms s) xms.
proof.
rewrite /G_MS_real /G_MS_after_binding /G0_real_qssm /mk_ms_game_view.
rewrite /ms1_hash_binding_step /=.
exists
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageReal;
    msgv_le_placeholder = None |}
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterBinding;
    msgv_le_placeholder = None |}.
by [].
qed.

lemma A_MS1_hash_binding_transition :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    ms_game_real_stage (G_MS_real x xms s) =>
    ms_game_after_binding_stage (G_MS_after_binding x xms s) =>
    ms_game_view_ms_pub (G_MS_real x xms s) xms =>
    ms_game_view_ms_pub (G_MS_after_binding x xms s) xms =>
    ms_game_view_qssm_seed (G_MS_real x xms s) x s =>
    ms_game_view_qssm_seed (G_MS_after_binding x xms s) x s =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms_hash_binding.
proof.
move=> x xms s D Hh _ _ _ _ _ _.
exact (A_MS1_canonical_hash_binding_bound x xms s D Hh).
qed.

lemma L_ms2_rom_programming_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms2_rom_programming_step (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) xms.
proof.
rewrite /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view.
rewrite /ms2_rom_programming_step /=.
exists
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterBinding;
    msgv_le_placeholder = None |}
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterRom;
    msgv_le_placeholder = None |}.
by [].
qed.

lemma A_MS2_rom_programming_transition :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    ms_game_after_binding_stage (G_MS_after_binding x xms s) =>
    ms_game_after_rom_stage (G_MS_after_rom x xms s) =>
    ms_game_view_ms_pub (G_MS_after_binding x xms s) xms =>
    ms_game_view_ms_pub (G_MS_after_rom x xms s) xms =>
    ms_game_view_qssm_seed (G_MS_after_binding x xms s) x s =>
    ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability.
proof.
move=> x xms s D Hr _ _ _ _ _ _.
exact (A_MS2_canonical_rom_programming_bound x xms s D Hr).
qed.

lemma L_ms3a_bitness_exact_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms3a_bitness_real_sim_equiv xms s =>
  ms3a_bitness_exact_step (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) xms s.
proof.
move=> Hequiv.
split; first exact Hequiv.
rewrite /G_MS_after_rom /G_MS_after_bitness /mk_ms_game_view.
exists
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterRom;
    msgv_le_placeholder = None |}
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterBitness;
    msgv_le_placeholder = None |}.
by [].
qed.

lemma A_MS3a_bitness_transition :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms_game_after_rom_stage (G_MS_after_rom x xms s) =>
    ms_game_after_bitness_stage (G_MS_after_bitness x xms s) =>
    ms_game_view_ms_pub (G_MS_after_rom x xms s) xms =>
    ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms =>
    ms_game_view_qssm_seed (G_MS_after_rom x xms s) x s =>
    ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s =>
    ms3a_bitness_real_sim_equiv xms s =>
    Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r.
proof.
move=> x xms s D _ _ _ _ _ _ H3a.
exact (A_MS3a_canonical_bitness_exact_bound x xms s D H3a).
qed.

lemma L_ms3b_true_clause_exact_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
    ms3b_comparison_operand_bits xms vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms_true_clause_position vb tb p =>
    ms3b_clause_opening_binds xms vb tb p clause_pub r =>
    ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
  ms3b_true_clause_exact_step (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) xms.
proof.
move=> H3b.
split; first exact H3b.
rewrite /G_MS_after_bitness /G_MS_after_comparison /mk_ms_game_view.
exists
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterBitness;
    msgv_le_placeholder = None |}
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterComparison;
    msgv_le_placeholder = None |}.
by [].
qed.

lemma A_MS3b_true_clause_transition :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms_game_after_bitness_stage (G_MS_after_bitness x xms s) =>
    ms_game_after_comparison_stage (G_MS_after_comparison x xms s) =>
    ms_game_view_ms_pub (G_MS_after_bitness x xms s) xms =>
    ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms =>
    ms_game_view_qssm_seed (G_MS_after_bitness x xms s) x s =>
    ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s =>
    (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
      ms3b_comparison_operand_bits xms vb tb =>
      ms_highest_differing_bit vb tb p =>
      ms_true_clause_position vb tb p =>
      ms3b_clause_opening_binds xms vb tb p clause_pub r =>
      ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
    Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D <= 0%r.
proof.
move=> x xms s D _ _ _ _ _ _ H3b.
exact (A_MS3b_canonical_true_clause_bound x xms s D H3b).
qed.

lemma L_ms3c_comparison_exact_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  (ms3c_comparison_query_digest_ann_only xms s =>
    ms3c_comparison_global_programmable_under_A2 xms s =>
    ms3c_false_clauses_simulator_generated xms s =>
    ms3c_true_clause_schnorr_from_blinder xms s =>
    ms3c_clause_challenge_shares_sum xms s =>
    ms_comparison_exact_simulation_equiv xms s) =>
  ms3c_comparison_exact_step (G_MS_after_comparison x xms s) (G_MS_sim x xms s) xms s.
proof.
move=> H3c.
split; first exact H3c.
rewrite /G_MS_after_comparison /G_MS_sim /G1_ms_sim_le_real /mk_ms_game_view.
exists
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageAfterComparison;
    msgv_le_placeholder = None |}
  {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
    msgv_ms_obs = witness; msgv_stage = MSGameStageSim;
    msgv_le_placeholder = None |}.
by [].
qed.

lemma A_MS3c_comparison_transition :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms_game_after_comparison_stage (G_MS_after_comparison x xms s) =>
    ms_game_sim_stage (G_MS_sim x xms s) =>
    ms_game_view_ms_pub (G_MS_after_comparison x xms s) xms =>
    ms_game_view_ms_pub (G_MS_sim x xms s) xms =>
    ms_game_view_qssm_seed (G_MS_after_comparison x xms s) x s =>
    ms_game_view_qssm_seed (G_MS_sim x xms s) x s =>
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    Adv (G_MS_after_comparison x xms s) (G_MS_sim x xms s) D <= 0%r.
proof.
move=> x xms s D _ _ _ _ _ _ H3c.
exact (A_MS3c_canonical_comparison_exact_bound x xms s D H3c).
qed.
