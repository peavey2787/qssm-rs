require import AllCore List.
require import QssmTypes Algebra Simulator FS TrueClause Comparison.
require import SourceDistributions SourceTheorem MS LEModel.

(* ------------------------------------------------------------------------- *)
(* MS game view constructors (structured `GV_ms` payloads).                 *)
(* ------------------------------------------------------------------------- *)
op mk_ms_game_view (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (obs : ms_transcript_observable) (st : ms_game_stage)
  (lep : le_transcript_observable option) : game_view =
  GV_ms {|
    msgv_qssm_pub = x;
    msgv_seed = s;
    msgv_ms_pub = xms;
    msgv_ms_obs = obs;
    msgv_stage = st;
    msgv_le_placeholder = lep;
  |}.

pred ms_game_view_is_ms (v : game_view) =
  exists (r : ms_game_view_record), v = GV_ms r.

pred ms_game_view_stage (v : game_view) (st : ms_game_stage) =
  exists (r : ms_game_view_record), v = GV_ms r /\ r.`msgv_stage = st.

pred ms_game_view_ms_pub (v : game_view) (xms : ms_public_input) =
  exists (r : ms_game_view_record), v = GV_ms r /\ r.`msgv_ms_pub = xms.

pred ms_game_view_qssm_seed (v : game_view) (x : qssm_public_input) (s : seed) =
  exists (r : ms_game_view_record), v = GV_ms r /\
    r.`msgv_qssm_pub = x /\ r.`msgv_seed = s.

pred ms_game_real_stage (v : game_view) =
  ms_game_view_stage v MSGameStageReal.

pred ms_game_after_binding_stage (v : game_view) =
  ms_game_view_stage v MSGameStageAfterBinding.

pred ms_game_after_rom_stage (v : game_view) =
  ms_game_view_stage v MSGameStageAfterRom.

pred ms_game_after_bitness_stage (v : game_view) =
  ms_game_view_stage v MSGameStageAfterBitness.

pred ms_game_after_comparison_stage (v : game_view) =
  ms_game_view_stage v MSGameStageAfterComparison.

pred ms_game_sim_stage (v : game_view) =
  ms_game_view_stage v MSGameStageSim.

(* QSSM top-level games: G0/G1 are MS-structured at chosen `xms`; G2 is a shell. *)
op G0_real_qssm (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageReal None.

op G1_ms_sim_le_real (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageSim None.

op G2_full_sim (x : qssm_public_input) (s : seed) : game_view =
  GV_g2_full_sim {| qg2_pub = x; qg2_seed = s |}.

op game_pr : game_view -> distinguisher -> real.
op Adv : game_view -> game_view -> distinguisher -> real.

axiom Adv_def :
  forall (v1 v2 : game_view) (D : distinguisher),
    Adv v1 v2 D = game_pr v1 D - game_pr v2 D.

op Adv_G0_G1_MS (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G0_real_qssm x xms s) (G1_ms_sim_le_real x xms s) D.

op Adv_G1_G2_LE (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G1_ms_sim_le_real x xms s) (G2_full_sim x s) D.

op Adv_G0_G2_QSSM (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher) : real =
  Adv (G0_real_qssm x xms s) (G2_full_sim x s) D.

(* MS sub-chain inside G0→G1 (same `xms` payload as the QSSM MS slice). *)
op G_MS_real (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  G0_real_qssm x xms s.

op G_MS_after_binding (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageAfterBinding None.

op G_MS_after_rom (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageAfterRom None.

op G_MS_after_bitness (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageAfterBitness None.

op G_MS_after_comparison (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageAfterComparison None.

op G_MS_sim (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  G1_ms_sim_le_real x xms s.

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

(* Telescoping identity: end-to-end MS advantage equals sum of segment advs. *)
lemma A_adv_ms_hop_telescope (xq : qssm_public_input) (xms : ms_public_input) (sq : seed) (Dq : distinguisher) :
  Adv (G_MS_real xq xms sq) (G_MS_sim xq xms sq) Dq =
  Adv (G_MS_real xq xms sq) (G_MS_after_binding xq xms sq) Dq +
  Adv (G_MS_after_binding xq xms sq) (G_MS_after_rom xq xms sq) Dq +
  Adv (G_MS_after_rom xq xms sq) (G_MS_after_bitness xq xms sq) Dq +
  Adv (G_MS_after_bitness xq xms sq) (G_MS_after_comparison xq xms sq) Dq +
  Adv (G_MS_after_comparison xq xms sq) (G_MS_sim xq xms sq) Dq.
proof.
smt(Adv_def).
qed.

(* MS1: narrow hash-binding replacement hop (frozen MS observable boundary). *)
axiom A_MS1_hash_binding_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    ms1_hash_binding_step src dst xms =>
    Adv src dst D <= epsilon_ms_hash_binding.

lemma L_ms1_hash_binding_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms1_hash_binding_step (G_MS_real x xms s) (G_MS_after_binding x xms s) xms.
proof.
rewrite /G_MS_real /G_MS_after_binding /G0_real_qssm /mk_ms_game_view /=.
by smt().
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
exact (A_MS1_hash_binding_replacement_bound (G_MS_real x xms s) (G_MS_after_binding x xms s) xms D Hh (L_ms1_hash_binding_step_canonical x xms s)).
qed.

(* MS2: narrow ROM/FS programming hop (frozen MS observable boundary). *)
axiom A_MS2_rom_programming_replacement_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    ms2_rom_programming_step src dst xms =>
    Adv src dst D <= epsilon_ms_rom_programmability.

lemma L_ms2_rom_programming_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms2_rom_programming_step (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) xms.
proof.
rewrite /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
by smt().
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
exact (A_MS2_rom_programming_replacement_bound (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) xms D Hr (L_ms2_rom_programming_step_canonical x xms s)).
qed.

(* MS3a: bitness exact-simulation hop (ROM -> bitness stage; `ms3a_bitness_real_sim_equiv` in predicate). *)
axiom A_MS3a_bitness_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_exact_step src dst xms s =>
    Adv src dst D <= 0%r.

lemma L_ms3a_bitness_exact_step_canonical (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms3a_bitness_real_sim_equiv xms s =>
  ms3a_bitness_exact_step (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) xms s.
proof.
move=> Hequiv.
split; first exact Hequiv.
rewrite /G_MS_after_rom /G_MS_after_bitness /mk_ms_game_view /=.
by smt().
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
exact (A_MS3a_bitness_exact_step_bound (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) xms s D (L_ms3a_bitness_exact_step_canonical x xms s H3a)).
qed.

(* MS3b: true-clause hop (bitness -> comparison stage; MS-3b forall bundle in predicate). *)
axiom A_MS3b_true_clause_exact_step_bound :
  forall (src dst : game_view) (xms : ms_public_input) (D : distinguisher),
    ms3b_true_clause_exact_step src dst xms =>
    Adv src dst D <= 0%r.

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
rewrite /G_MS_after_bitness /G_MS_after_comparison /mk_ms_game_view /=.
by smt().
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
exact (A_MS3b_true_clause_exact_step_bound (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) xms D (L_ms3b_true_clause_exact_step_canonical x xms s H3b)).
qed.

axiom A_MS3c_comparison_transition :
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

(* Standard game-hop arithmetic over advantage differences. *)
lemma A_adv_gamehop_triangle :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    Adv_G0_G2_QSSM x xms s D <= Adv_G0_G1_MS x xms s D + Adv_G1_G2_LE x xms s D.
proof.
move=> x xms s D.
rewrite /Adv_G0_G2_QSSM /Adv_G0_G1_MS /Adv_G1_G2_LE.
rewrite !(Adv_def _ _ D).
smt().
qed.

(* G0→G1 MS hop: composed bound from MS1..MS3c segment obligations + telescope. *)
lemma A_G0_to_G1_ms_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    0%r <= epsilon_ms_rom_programmability =>
    ms3a_bitness_real_sim_equiv xms s =>
    (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
      ms3b_comparison_operand_bits xms vb tb =>
      ms_highest_differing_bit vb tb p =>
      ms_true_clause_position vb tb p =>
      ms3b_clause_opening_binds xms vb tb p clause_pub r =>
      ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    Adv_G0_G1_MS x xms s D <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability.
proof.
move=> x xms s D Hh Hr H3a H3b H3c.
have Htel := A_adv_ms_hop_telescope x xms s D.
rewrite /G_MS_real /G_MS_sim in Htel.
have [H1a [H1b [H1c [H1d [H1e H1f]]]]] := L_ms_MS1_stage_premises x xms s.
have [H2a [H2b [H2c [H2d [H2e H2f]]]]] := L_ms_MS2_stage_premises x xms s.
have [HS3arom [HS3abit [HS3ap1 [HS3ap2 [HS3aq1 HS3aq2]]]]] := L_ms_MS3a_stage_premises x xms s.
have [HS3bbit [HS3bcomp [HS3bp1 [HS3bp2 [HS3bq1 HS3bq2]]]]] := L_ms_MS3b_stage_premises x xms s.
have [HS3ccomp [HS3csim [HS3cp1 [HS3cp2 [HS3cq1 HS3cq2]]]]] := L_ms_MS3c_stage_premises x xms s.
have H1 := A_MS1_hash_binding_transition x xms s D Hh H1a H1b H1c H1d H1e H1f.
have H2 := A_MS2_rom_programming_transition x xms s D Hr H2a H2b H2c H2d H2e H2f.
have H3 := A_MS3a_bitness_transition x xms s D HS3arom HS3abit HS3ap1 HS3ap2 HS3aq1 HS3aq2 H3a.
have H4 := A_MS3b_true_clause_transition x xms s D HS3bbit HS3bcomp HS3bp1 HS3bp2 HS3bq1 HS3bq2 H3b.
have H5 := A_MS3c_comparison_transition x xms s D HS3ccomp HS3csim HS3cp1 HS3cp2 HS3cq1 HS3cq2 H3c.
rewrite /Adv_G0_G1_MS /G_MS_real /G_MS_sim.
rewrite Htel.
by smt().
qed.

lemma A_G1_to_G2_le_transition_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    Adv_G1_G2_LE x xms s D = le_game_hop_adv x s D =>
    Adv_G1_G2_LE x xms s D <= epsilon_le.
proof.
move=> x xms s D Hsetb Heps Hleeqv Heq.
have Hhvzk := A_LE_HVZK_transition_bound x s D Hsetb Heps Hleeqv.
rewrite /le_hvzk_transition_bound in Hhvzk.
by rewrite Heq; exact Hhvzk.
qed.
