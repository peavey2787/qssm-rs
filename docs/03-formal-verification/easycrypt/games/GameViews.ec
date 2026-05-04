require import AllCore List.
require import QssmTypes SourceModel.
require import TranscriptObservable.
require import GameTypes.

op ms_game_view_public_obs (xms : ms_public_input) : ms_v2_transcript_observable =
  ms3a_public_v2_observable xms.

(* QSSM top-level games: G0/G1 are MS-structured at chosen `xms`; G2 is a shell. *)
op G0_real_qssm (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageReal None.

op G1_ms_sim_le_real (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageSim None.

op G2_full_sim (x : qssm_public_input) (s : seed) : game_view =
  GV_g2_full_sim {| qg2_pub = x; qg2_seed = s |}.

(* MS sub-chain inside G0→G1 (same `xms` payload as the QSSM MS slice). *)
op G_MS_real (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  G0_real_qssm x xms s.

op G_MS_after_binding (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None.

op G_MS_after_rom (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageAfterRom None.

op G_MS_after_bitness (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageAfterBitness None.

op G_MS_after_comparison (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms (ms_game_view_public_obs xms) MSGameStageAfterComparison None.

op G_MS_sim (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  G1_ms_sim_le_real x xms s.

lemma L_ms_game_view_stage_mk (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (obs : ms_v2_transcript_observable) (st : ms_game_stage)
  (lep : le_transcript_observable option) :
  ms_game_view_stage (mk_ms_game_view x s xms obs st lep) st.
proof.
rewrite /ms_game_view_stage /mk_ms_game_view /=.
exists {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
  msgv_ms_obs = obs; msgv_stage = st; msgv_le_placeholder = lep |}.
by [].
qed.

lemma L_ms_game_view_ms_pub_mk (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (obs : ms_v2_transcript_observable) (st : ms_game_stage)
  (lep : le_transcript_observable option) :
  ms_game_view_ms_pub (mk_ms_game_view x s xms obs st lep) xms.
proof.
rewrite /ms_game_view_ms_pub /mk_ms_game_view /=.
exists {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
  msgv_ms_obs = obs; msgv_stage = st; msgv_le_placeholder = lep |}.
by [].
qed.

lemma L_ms_game_view_qssm_seed_mk (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (obs : ms_v2_transcript_observable) (st : ms_game_stage)
  (lep : le_transcript_observable option) :
  ms_game_view_qssm_seed (mk_ms_game_view x s xms obs st lep) x s.
proof.
rewrite /ms_game_view_qssm_seed /mk_ms_game_view /=.
exists {| msgv_qssm_pub = x; msgv_seed = s; msgv_ms_pub = xms;
  msgv_ms_obs = obs; msgv_stage = st; msgv_le_placeholder = lep |}.
by [].
qed.

lemma L_ms_game_after_binding_stage_G (x : qssm_public_input) (xms : ms_public_input) (s : seed) :
  ms_game_after_binding_stage (G_MS_after_binding x xms s).
proof.
rewrite /ms_game_after_binding_stage /G_MS_after_binding.
apply (L_ms_game_view_stage_mk x s xms (ms_game_view_public_obs xms) MSGameStageAfterBinding None).
qed.
