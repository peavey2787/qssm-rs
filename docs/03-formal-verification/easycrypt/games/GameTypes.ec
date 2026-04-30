require import AllCore List.
require import QssmTypes.

(* ------------------------------------------------------------------------- *)
(* MS game view constructors and shape predicates.                           *)
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
