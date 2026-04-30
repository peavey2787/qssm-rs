require import AllCore List.
require import QssmTypes.
require import GameTypes.

(* QSSM top-level games: G0/G1 are MS-structured at chosen `xms`; G2 is a shell. *)
op G0_real_qssm (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageReal None.

op G1_ms_sim_le_real (x : qssm_public_input) (xms : ms_public_input) (s : seed) : game_view =
  mk_ms_game_view x s xms witness MSGameStageSim None.

op G2_full_sim (x : qssm_public_input) (s : seed) : game_view =
  GV_g2_full_sim {| qg2_pub = x; qg2_seed = s |}.

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
