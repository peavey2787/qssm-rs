require import AllCore List Ring.
require import StdOrder.
(*---*) import RealOrder.
require import QssmTypes Algebra Simulator FS TrueClause Comparison ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayload ComparisonCoupling ComparisonCouplingTypes ComparisonCouplingAxioms ComparisonCouplingTheorem ComparisonTheorem.
require import SourceModel.
require import SourceDistributions SourceTheorem MS LESurface LEModel.
require import SourceHashBindingSemanticBridge ComparisonPayloadSemanticBridge.
require import GameTypes GameViews GameAdvantage.
require import TranscriptObservable.

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

lemma L_ms_MS3c_public_obs_matches_phase1_payload
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  let obs = ms_game_view_public_obs xms in
  (ms3c_phase1_payload_from_public_input xms).`mscp_programmed_challenge =
    ms3c_obs_programmed_challenge obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_global_challenge =
    ms_comparison_global_challenge obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_share_true =
    ms3c_obs_share_true obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_ann_true =
    ms3c_obs_ann_true obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_share_false =
    ms3c_obs_shares_false obs /\
  (ms3c_phase1_payload_from_public_input xms).`mscp_ann_false =
    ms3c_obs_anns_false obs.
proof.
have Halign := L_ms3c_public_obs_payload_alignment xms.
move: Halign.
by case: (ms_game_view_public_obs xms).
qed.

lemma L_ms_MS3c_public_obs_matches_phase1_seed
  (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  let obs = ms_game_view_public_obs xms in
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_stmt_digest =
    ms_statement_digest obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_true_clause_ix =
    ms3c_public_true_clause_index xms /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_false_clause_ixs =
    ms3c_public_false_clause_indices xms /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_share_true =
    ms3c_obs_share_true obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_share_false =
    ms3c_obs_shares_false obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_global_challenge =
    ms_comparison_global_challenge obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_programmed_challenge =
    ms3c_obs_programmed_challenge obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`1.`ms3csc_query_digest =
    ms3c_phase1_seed_query_digest xms /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`2.`ms3csa_ann_true =
    ms3c_obs_ann_true obs /\
  (ms3c_phase1_real_payload_seed_from_public_input xms).`2.`ms3csa_ann_false =
    ms3c_obs_anns_false obs /\
  ms3c_phase1_sim_payload_seed_from_public_input xms s =
    ms3c_phase1_real_payload_seed_from_public_input xms.
proof.
rewrite /ms3c_phase1_real_payload_seed_from_public_input /=.
have [Hstmt [Htrue_ix [Hfalse_ixs [Hshare_true [Hshare_false [Hglob [Hprog [Hquery [Hann_true Hann_false]]]]]]]]]
  := L_ms3c_public_obs_seed_alignment xms.
have Hsim := L_ms3c_phase1_real_sim_payload_seed_from_public_input xms s.
rewrite /ms3c_phase1_real_payload_seed_from_public_input in Hsim.
split; first exact Hstmt.
split; first exact Htrue_ix.
split; first exact Hfalse_ixs.
split; first exact Hshare_true.
split; first exact Hshare_false.
split; first exact Hglob.
split; first exact Hprog.
split; first exact Hquery.
split; first exact Hann_true.
split; first exact Hann_false.
exact Hsim.
qed.

(* MS1 hash-binding theorem surface: `GameAdvantage.ec` now computes
  `game_pr_ms_core` from the concrete lower MS probability surface, and the
  lower Real/AfterBinding bound there is a proved lemma. This concrete GV_ms
  pair theorem is obtained by unfolding `Adv` and `game_pr` to that boundary. *)
lemma A_MS1_hash_binding_concrete_pair_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    Adv
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageReal;
                msgv_le_placeholder = lep |})
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterBinding;
                msgv_le_placeholder = lep |})
      D <= epsilon_ms_hash_binding.
    proof.
    move=> x s xms obs lep D Hnonneg.
    rewrite /Adv /game_pr /= /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
    exact (A_MS1_hash_binding_game_pr_core_bound x s xms obs lep D Hnonneg).
    qed.

lemma A_MS1_canonical_hash_binding_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_hash_binding =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= epsilon_ms_hash_binding.
proof.
move=> x xms s D Hnonneg.
rewrite /G_MS_real /G_MS_after_binding /G0_real_qssm /mk_ms_game_view /=.
exact (A_MS1_hash_binding_concrete_pair_advantage_bound
  x s xms (ms_game_view_public_obs xms) None D Hnonneg).
qed.

lemma A_MS1_hash_binding_semantic_concrete_pair_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= MS.epsilon_ms_hash_binding_semantic =>
    Adv
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageReal;
                msgv_le_placeholder = lep |})
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterBinding;
                msgv_le_placeholder = lep |})
      D <= MS.epsilon_ms_hash_binding_semantic.
proof.
move=> x s xms obs lep D Hnonneg.
rewrite /Adv /game_pr /= /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
exact (A_MS1_hash_binding_semantic_game_pr_core_bound x s xms obs lep D Hnonneg).
qed.

lemma A_MS1_canonical_hash_binding_semantic_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= MS.epsilon_ms_hash_binding_semantic =>
    Adv (G_MS_real x xms s) (G_MS_after_binding x xms s) D <= MS.epsilon_ms_hash_binding_semantic.
proof.
move=> x xms s D Hnonneg.
rewrite /G_MS_real /G_MS_after_binding /G0_real_qssm /mk_ms_game_view /=.
exact (A_MS1_hash_binding_semantic_concrete_pair_advantage_bound
  x s xms (ms_game_view_public_obs xms) None D Hnonneg).
qed.

(* MS2 ROM-programming theorem surface: the lower bridge in
  `GameAdvantage.ec` is now a proved lemma on `game_pr_ms_core`; this concrete
  GV_ms pair theorem is obtained by unfolding `Adv` and `game_pr` down to that
  boundary. *)
lemma A_MS2_rom_programming_concrete_pair_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    Adv
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterBinding;
                msgv_le_placeholder = lep |})
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterRom;
                msgv_le_placeholder = lep |})
      D <= epsilon_ms_rom_programmability.
    proof.
    move=> x s xms obs lep D Hnonneg.
    rewrite /Adv /game_pr /= /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
    exact (A_MS2_rom_programming_game_pr_core_bound x s xms obs lep D Hnonneg).
    qed.

lemma A_MS2_rom_programming_semantic_concrete_pair_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability_semantic =>
    Adv
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterBinding;
                msgv_le_placeholder = lep |})
      (GV_ms {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
                msgv_ms_obs = obs; msgv_stage = MSGameStageAfterRom;
                msgv_le_placeholder = lep |})
      D <= epsilon_ms_rom_programmability_semantic.
proof.
move=> x s xms obs lep D Hnonneg.
rewrite /Adv /game_pr /= /ms3a_game_pr_stage /ms3b_game_pr_stage /ms3c_game_pr_stage /=.
exact (A_MS2_rom_programming_semantic_game_pr_core_bound x s xms obs lep D Hnonneg).
qed.

lemma A_MS2_canonical_rom_programming_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability.
proof.
move=> x xms s D Hnonneg.
rewrite /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
exact (A_MS2_rom_programming_concrete_pair_advantage_bound
  x s xms (ms_game_view_public_obs xms) None D Hnonneg).
qed.

lemma A_MS2_canonical_rom_programming_semantic_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    0%r <= epsilon_ms_rom_programmability_semantic =>
    Adv (G_MS_after_binding x xms s) (G_MS_after_rom x xms s) D <= epsilon_ms_rom_programmability_semantic.
proof.
move=> x xms s D Hnonneg.
rewrite /G_MS_after_binding /G_MS_after_rom /mk_ms_game_view /=.
exact (A_MS2_rom_programming_semantic_concrete_pair_advantage_bound
  x s xms (ms_game_view_public_obs xms) None D Hnonneg).
qed.

(* Staged public-endpoint wrapper surface: these are thin aliases over the
   parallel GameAdvantage core and remain unused by the canonical telescope. *)
lemma A_MS_public_endpoint_staged_semantic_transition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      MS.epsilon_ms_hash_binding_semantic +
      epsilon_ms_rom_programmability_semantic.
proof.
move=> x s xms D.
exact (A_MS_public_endpoint_semantic_transition_bound x s xms D).
qed.

lemma A_MS_public_endpoint_staged_visible_flags_transition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      MS.epsilon_ms_hash_binding_semantic +
      ((if ms_rom_public_divergence_global_digest_flag xms then
          (BudgetParameters.ms_rom_query_collision_slot_count +
           BudgetParameters.ms_rom_programming_collision_slot_count)%r
        else 0%r) +
       (if ms_rom_public_divergence_query_digest_flag xms then
          BudgetParameters.ms_rom_transcript_mismatch_slot_count%r
        else 0%r)) /
      BudgetParameters.ms_rom_total_slot_count%r.
proof.
move=> x s xms D.
exact (A_MS_public_endpoint_visible_flags_transition_bound x s xms D).
qed.

lemma A_MS_public_endpoint_staged_local_visible_flags_transition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      ms_hash_binding_local_public_divergence_upper_mass +
      ((if ms_rom_public_divergence_global_digest_flag xms then
          (BudgetParameters.ms_rom_query_collision_slot_count +
           BudgetParameters.ms_rom_programming_collision_slot_count)%r
        else 0%r) +
       (if ms_rom_public_divergence_query_digest_flag xms then
          BudgetParameters.ms_rom_transcript_mismatch_slot_count%r
        else 0%r)) /
      BudgetParameters.ms_rom_total_slot_count%r.
proof.
move=> x s xms D.
exact (A_MS_public_endpoint_local_visible_flags_transition_bound x s xms D).
qed.

lemma A_MS_public_endpoint_staged_local_visible_flags_closed_form_transition_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint x s xms D <=
      1%r / 8%r +
      ((if ms_rom_public_divergence_global_digest_flag xms then
          (BudgetParameters.ms_rom_query_collision_slot_count +
           BudgetParameters.ms_rom_programming_collision_slot_count)%r
        else 0%r) +
       (if ms_rom_public_divergence_query_digest_flag xms then
          BudgetParameters.ms_rom_transcript_mismatch_slot_count%r
        else 0%r)) /
      BudgetParameters.ms_rom_total_slot_count%r.
proof.
move=> x s xms D.
exact (A_MS_public_endpoint_local_visible_flags_closed_form_transition_bound x s xms D).
qed.

(* MS3a canonical bitness exact-simulation bound on the concrete stage pair
  used in the G0->G1 telescope. With `game_pr` now projected from `game_view`,
  the canonical AfterRom/AfterBitness views become probability-equal whenever
  `ms3a_bitness_real_sim_equiv` holds, so the advantage is exactly zero. *)
lemma A_MS3a_canonical_bitness_exact_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    ms3a_bitness_real_sim_equiv xms s =>
    Adv (G_MS_after_rom x xms s) (G_MS_after_bitness x xms s) D <= 0%r.
proof.
move=> x xms s D Hequiv.
rewrite Adv_def /Adv /game_pr /G_MS_after_rom /G_MS_after_bitness /mk_ms_game_view /=.
have Hst_rom : ms3a_game_pr_stage xms s MSGameStageAfterRom = MSGameStageAfterRom.
- rewrite /ms3a_game_pr_stage Hequiv /=.
  by [].
have Hst_bit : ms3a_game_pr_stage xms s MSGameStageAfterBitness = MSGameStageAfterRom.
- rewrite /ms3a_game_pr_stage Hequiv /=.
  by [].
rewrite Hst_rom Hst_bit.
have -> :
  game_pr_ms_core x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None D -
  game_pr_ms_core x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None D = 0%r
  by ring.
by [].
qed.

(* MS3b canonical true-clause obligation on the concrete stage pair used in the
   G0->G1 telescope. The source theorem `MS_3b_true_clause_characterization`
   proves the required forall-bundle, and the projected `game_pr` surface makes
   AfterBitness and AfterComparison coincide under that bundle, so the
   resulting advantage is exactly zero. *)
lemma A_MS3b_canonical_true_clause_bound :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
      ms3b_comparison_operand_bits xms vb tb =>
      ms_highest_differing_bit vb tb p =>
      ms_true_clause_position vb tb p =>
      ms3b_clause_opening_binds xms vb tb p clause_pub r =>
      ms_true_clause_points_are_blinder_points vb tb p clause_pub r) =>
    Adv (G_MS_after_bitness x xms s) (G_MS_after_comparison x xms s) D <= 0%r.
proof.
move=> x xms s D _.
have Htrue : ms3b_true_clause_game_pr_equiv xms.
- move=> vb tb p clause_pub r Hop Hhd Htcp Hob.
  exact (MS_3b_true_clause_characterization xms vb tb p clause_pub r Hop Hhd Htcp Hob).
rewrite Adv_def /Adv /game_pr /G_MS_after_bitness /G_MS_after_comparison /mk_ms_game_view /=.
have Hst_bit : ms3b_game_pr_stage xms MSGameStageAfterBitness = MSGameStageAfterBitness.
- rewrite /ms3b_game_pr_stage Htrue /=.
  by [].
have Hst_cmp : ms3b_game_pr_stage xms MSGameStageAfterComparison = MSGameStageAfterBitness.
- rewrite /ms3b_game_pr_stage Htrue /=.
  by [].
rewrite Hst_bit Hst_cmp.
have -> :
  game_pr_ms_core x s xms (ms_game_view_public_obs xms)
    (ms3a_game_pr_stage xms s MSGameStageAfterBitness) None D -
  game_pr_ms_core x s xms (ms_game_view_public_obs xms)
    (ms3a_game_pr_stage xms s MSGameStageAfterBitness) None D = 0%r
  by ring.
by [].
qed.

(* MS3c game layer: the comparison MS-3c implication bundle (same shape as
  `ms3c_comparison_exact_step` / `MS_3c_exact_comparison_simulation`) now
  collapses the two canonical stage views directly inside `game_pr` through
  `ms3c_game_pr_stage`. The schedule-level fact
  `ms_comparison_exact_simulation_equiv` is still proved in `ms/comparison/`,
  but the game-layer bridge is now definitional rather than axiomatic. *)
lemma A_MS3c_comparison_bundle_implies_game_pr_equality :
  forall (x : qssm_public_input) (xms : ms_public_input) (s : seed) (D : distinguisher),
    (ms3c_comparison_query_digest_ann_only xms s =>
      ms3c_comparison_global_programmable_under_A2 xms s =>
      ms3c_false_clauses_simulator_generated xms s =>
      ms3c_true_clause_schnorr_from_blinder xms s =>
      ms3c_clause_challenge_shares_sum xms s =>
      ms_comparison_exact_simulation_equiv xms s) =>
    game_pr (G_MS_after_comparison x xms s) D = game_pr (G_MS_sim x xms s) D.
proof.
move=> x xms s D Hequiv.
rewrite /game_pr /G_MS_after_comparison /G_MS_sim /G1_ms_sim_le_real /mk_ms_game_view /=.
have Hcmp : ms3c_comparison_game_pr_equiv xms s.
- exact Hequiv.
have Hst_cmp :
    ms3c_game_pr_stage xms s MSGameStageAfterComparison = MSGameStageAfterComparison.
- rewrite /ms3c_game_pr_stage Hcmp /=.
  by [].
have Hst_sim :
    ms3c_game_pr_stage xms s MSGameStageSim = MSGameStageAfterComparison.
- rewrite /ms3c_game_pr_stage Hcmp /=.
  by [].
rewrite Hst_cmp Hst_sim.
by [].
qed.

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
  obligations are the MS1/MS2 narrow axioms plus the proved MS3a/MS3b/MS3c
  canonical lemmas in this file; `A_MS3c_canonical_comparison_exact_bound` is
  now a proved lemma from `Adv_def` and the definitional MS3c stage collapse. *)
