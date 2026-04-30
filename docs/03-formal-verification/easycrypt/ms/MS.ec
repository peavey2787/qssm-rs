require import AllCore List.
require import Algebra QssmTypes Comparison.
require import SourceDistributions.
require import TrueClause.

(* MS façade: simulator transcript hooks, hash-binding budget, MS-3c wrapper.
   MS-3a observable frame lives in `ms/SourceModel.ec`; source/types/distributions
   and MS-3a theorems live under `ms/source/`. *)

op ms_real_transcript (xms : ms_public_input) : game_view =
  GV_ms {|
    msgv_qssm_pub = witness;
    msgv_seed = witness;
    msgv_ms_pub = xms;
    msgv_ms_obs = witness;
    msgv_stage = MSGameStageReal;
    msgv_le_placeholder = None;
  |}.

op ms_sim_transcript (xms : ms_public_input) (s : seed) : game_view =
  GV_ms {|
    msgv_qssm_pub = witness;
    msgv_seed = s;
    msgv_ms_pub = xms;
    msgv_ms_obs = witness;
    msgv_stage = MSGameStageSim;
    msgv_le_placeholder = None;
  |}.

op epsilon_ms_hash_binding : real.

axiom A1_ms_hash_binding_nonneg :
  0%r <= epsilon_ms_hash_binding.

(* MS1 (hash-binding) hop interface: only the stage tag moves Real -> AfterBinding;
   QSSM/MS public slices, seed, LE placeholder, and MS transcript observable stay fixed.
   This is the semantic side of the hash-binding replacement step; the game-layer bound
   is `A_MS1_hash_binding_replacement_bound` in `games/Games.ec`, using the same
   `epsilon_ms_hash_binding` budget as `A1_ms_hash_binding_nonneg` / theorem-level `A1_ms_hash_binding`. *)
pred ms1_hash_binding_step (src dst : game_view) (xms : ms_public_input) =
  exists (r1 r2 : ms_game_view_record),
    src = GV_ms r1 /\
    dst = GV_ms r2 /\
    r1.`msgv_ms_pub = xms /\ r2.`msgv_ms_pub = xms /\
    r1.`msgv_ms_obs = r2.`msgv_ms_obs /\
    r1.`msgv_qssm_pub = r2.`msgv_qssm_pub /\
    r1.`msgv_seed = r2.`msgv_seed /\
    r1.`msgv_le_placeholder = r2.`msgv_le_placeholder /\
    r1.`msgv_stage = MSGameStageReal /\
    r2.`msgv_stage = MSGameStageAfterBinding.

(* MS2 (ROM / FS programmability) hop: only AfterBinding -> AfterRom; same QSSM/MS pub,
   seed, LE placeholder, and MS transcript observable on both sides. Game-layer bound:
   `A_MS2_rom_programming_replacement_bound` in `games/Games.ec` with budget
   `epsilon_ms_rom_programmability` from `primitives/FS.ec` (`A2_ms_rom_programmability_nonneg`,
   theorem-level `A2_ms_rom_programmability`; programmable oracle surface `A2_programmable_oracle_exists`). *)
pred ms2_rom_programming_step (src dst : game_view) (xms : ms_public_input) =
  exists (r1 r2 : ms_game_view_record),
    src = GV_ms r1 /\
    dst = GV_ms r2 /\
    r1.`msgv_ms_pub = xms /\ r2.`msgv_ms_pub = xms /\
    r1.`msgv_ms_obs = r2.`msgv_ms_obs /\
    r1.`msgv_qssm_pub = r2.`msgv_qssm_pub /\
    r1.`msgv_seed = r2.`msgv_seed /\
    r1.`msgv_le_placeholder = r2.`msgv_le_placeholder /\
    r1.`msgv_stage = MSGameStageAfterBinding /\
    r2.`msgv_stage = MSGameStageAfterRom.

(* MS3a bitness exact-simulation hop: AfterRom -> AfterBitness with frozen `GV_ms` fields;
   first conjunct is `ms3a_bitness_real_sim_equiv` (source/observable layer, `SourceTheorem`).
   Game-layer zero advantage: `A_MS3a_bitness_exact_step_bound` in `games/Games.ec`. *)
pred ms3a_bitness_exact_step (src dst : game_view) (xms : ms_public_input) (s : seed) =
  ms3a_bitness_real_sim_equiv xms s /\
  exists (r1 r2 : ms_game_view_record),
    src = GV_ms r1 /\
    dst = GV_ms r2 /\
    r1.`msgv_ms_pub = xms /\ r2.`msgv_ms_pub = xms /\
    r1.`msgv_ms_obs = r2.`msgv_ms_obs /\
    r1.`msgv_qssm_pub = r2.`msgv_qssm_pub /\
    r1.`msgv_seed = r2.`msgv_seed /\
    r1.`msgv_le_placeholder = r2.`msgv_le_placeholder /\
    r1.`msgv_stage = MSGameStageAfterRom /\
    r2.`msgv_stage = MSGameStageAfterBitness.

(* MS3b true-clause hop: AfterBitness -> AfterComparison; first conjunct is the MS-3b
   forall bundle (same hypotheses as `MS_3b_true_clause_characterization` in `TrueClause.ec`).
   Game-layer zero advantage: `A_MS3b_true_clause_exact_step_bound` in `games/Games.ec`. *)
pred ms3b_true_clause_exact_step (src dst : game_view) (xms : ms_public_input) =
  (forall (vb : bool list) (tb : bool list) (p : int) (clause_pub : sch_point) (r : scalar),
    ms3b_comparison_operand_bits xms vb tb =>
    ms_highest_differing_bit vb tb p =>
    ms_true_clause_position vb tb p =>
    ms3b_clause_opening_binds xms vb tb p clause_pub r =>
    ms_true_clause_points_are_blinder_points vb tb p clause_pub r) /\
  exists (r1 r2 : ms_game_view_record),
    src = GV_ms r1 /\
    dst = GV_ms r2 /\
    r1.`msgv_ms_pub = xms /\ r2.`msgv_ms_pub = xms /\
    r1.`msgv_ms_obs = r2.`msgv_ms_obs /\
    r1.`msgv_qssm_pub = r2.`msgv_qssm_pub /\
    r1.`msgv_seed = r2.`msgv_seed /\
    r1.`msgv_le_placeholder = r2.`msgv_le_placeholder /\
    r1.`msgv_stage = MSGameStageAfterBitness /\
    r2.`msgv_stage = MSGameStageAfterComparison.

(* MS-3a / MS-3b / MS-3c: MS-3a layered lemmas in `ms/source/SourceTheorem.ec`; MS-3b in
   `ms/TrueClause.ec`; MS-3c core in `ms/Comparison.ec` (narrow axioms +
   `ms_comparison_exact_*` pred). *)
(* G0→G1 game hop in `games/Games.ec` is decomposed into segment obligations
   `A_MS1_hash_binding_transition` / `A_MS2_rom_programming_transition` (lemmas from
   `A_MS1_hash_binding_replacement_bound` / `A_MS2_rom_programming_replacement_bound` +
   `ms1_hash_binding_step` / `ms2_rom_programming_step`), `A_MS3a_bitness_transition`
   (lemma from `A_MS3a_bitness_exact_step_bound` + `ms3a_bitness_exact_step`),
   `A_MS3b_true_clause_transition` (lemma from `A_MS3b_true_clause_exact_step_bound` +
   `ms3b_true_clause_exact_step`), … `A_MS3c_*`
   over intermediate views `G_MS_after_*`; the composed bound `A_G0_to_G1_ms_transition_bound`
   is a lemma (telescope + segment bounds). *)
(* MS-3a proof path (bitness only; games unchanged):
   `MS_3a_single_branch_schnorr_reparam` (`ms/SchnorrBranch.ec`)
   -> `MS_3a_single_bit_or_split_exact_simulation`
   -> `A2_bitness_programmed_challenge` (`primitives/FS.ec`)
   -> `MS_3a_bitness_layer_exact_simulation` (`ms/BitnessVector.ec`)
   -> `MS_3a_bitness_layer_to_observable_exact_simulation`
   -> `ms3a_frame_consistent` (alignment + digest on v2 record)
   -> `MS_3a_exact_bitness_simulation` (`ms/source/SourceTheorem.ec`; game marginals open). *)

lemma MS_3c_exact_comparison_simulation (x : ms_public_input) (s : seed) :
  ms3c_comparison_query_digest_ann_only x s =>
  ms3c_comparison_global_programmable_under_A2 x s =>
  ms3c_false_clauses_simulator_generated x s =>
  ms3c_true_clause_schnorr_from_blinder x s =>
  ms3c_clause_challenge_shares_sum x s =>
  ms_comparison_exact_simulation_equiv x s.
proof.
move=> Hann Ha2 Hfalse Htrue Hsum.
exact (MS_3c_exact_comparison_simulation_from_clauses x s Hann Ha2 Hfalse Htrue Hsum).
qed.
