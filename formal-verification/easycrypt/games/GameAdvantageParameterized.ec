require import AllCore.
require import StdOrder.
require import QssmTypes.
require import SourceTypes.
require import TranscriptObservable.
require import GameTypes.
require import MSProbabilitySurface.
require import MSProbabilitySurfaceParameterized.
require import SourceHashBindingSemanticSlotMassParameterized.
require import GameAdvantage.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Parallel parameterized game-advantage wrappers.
   Slice 2 adds a parameterized public-endpoint carrier for the MS1 staged lane
   while leaving the shared demo game wrappers untouched. *)

op d_ms_public_endpoint_after_binding_observable_v2_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms.

op d_ms_public_endpoint_after_rom_observable_v2_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input) :
  ms_v2_transcript_observable distr =
  d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms.

op d_ms_public_endpoint_stage_observable_v2_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (st : ms_public_endpoint_stage) : ms_v2_transcript_observable distr =
  with st = MSPublicEndpointAfterBinding =>
    d_ms_public_endpoint_after_binding_observable_v2_parameterized x s xms
  with st = MSPublicEndpointAfterRom =>
    d_ms_public_endpoint_after_rom_observable_v2_parameterized x s xms.

op game_pr_ms_public_endpoint_core_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (st : ms_public_endpoint_stage) (D : distinguisher) : real =
  ms_view_distinguish_pr
    (d_ms_public_endpoint_stage_observable_v2_parameterized x s xms st) D.

op Adv_ms_public_endpoint_parameterized
  (x : qssm_public_input) (s : seed) (xms : ms_public_input)
  (D : distinguisher) : real =
  game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterBinding D -
  game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterRom D.

lemma A_MS1_hash_binding_parameterized_game_pr_core_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    game_pr_ms_core x s xms obs MSGameStageReal lep D -
    game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D <=
      ParameterizedBudgetParameters.epsilon_ms_hash_binding_parameterized.
proof.
move=> x s xms obs lep D.
rewrite /game_pr_ms_core.
exact (A_MS1_hash_binding_parameterized_bad_event_bound x s xms D).
qed.

lemma A_MS1_hash_binding_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterBinding D -
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D <=
  ms_hash_binding_local_public_divergence_upper_mass_parameterized.
proof.
move=> x s xms D.
rewrite /game_pr_ms_public_endpoint_core_parameterized.
rewrite /d_ms_public_endpoint_stage_observable_v2_parameterized /=.
exact (A_MS1_hash_binding_parameterized_public_endpoint_compatibility_bound x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterRom D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
rewrite /game_pr_ms_public_endpoint_core_parameterized.
rewrite /d_ms_public_endpoint_stage_observable_v2_parameterized /=.
exact (A_MS2_rom_programming_parameterized_public_endpoint_transition_bound x s xms D).
qed.

lemma A_MS_public_after_rom_to_canonical_after_rom_parameterized_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterRom D -
    game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms obs lep D.
rewrite /game_pr_ms_public_endpoint_core_parameterized /game_pr_ms_core.
rewrite /d_ms_public_endpoint_stage_observable_v2_parameterized /d_ms_game_stage_observable_v2 /=.
exact (A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound x s xms D).
qed.

lemma A_MS2_rom_programming_parameterized_canonical_game_pr_core_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    game_pr_ms_core x s xms obs MSGameStageAfterBinding lep D -
    game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <=
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms obs lep D.
rewrite /game_pr_ms_core /d_ms_game_stage_observable_v2 /=.
have Hpublic :=
  A_MS2_rom_programming_parameterized_public_endpoint_transition_bound x s xms D.
have Hland :=
  A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound x s xms D.
have -> :
    ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D =
    (ms_view_distinguish_pr (d_ms_after_binding_observable_v2 x s xms) D -
   ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
  (ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D).
  by ring.
exact (ler_add _ _ _ _ Hpublic Hland).
qed.

lemma A_MS_public_endpoint_to_canonical_parameterized_game_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (obs : ms_v2_transcript_observable)
         (lep : le_transcript_observable option) (D : distinguisher),
    game_pr_ms_public_endpoint_core_parameterized x s xms MSPublicEndpointAfterBinding D -
    game_pr_ms_core x s xms obs MSGameStageAfterRom lep D <=
      ms_hash_binding_local_public_divergence_upper_mass_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms obs lep D.
rewrite /game_pr_ms_public_endpoint_core_parameterized /game_pr_ms_core.
rewrite /d_ms_public_endpoint_stage_observable_v2_parameterized /d_ms_game_stage_observable_v2 /=.
have Hpublic := A_MS_public_endpoint_parameterized_transition_bound x s xms D.
have Hland :=
  A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound x s xms D.
have -> :
    ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
    ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D =
    (ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
   ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
  (ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D).
  by ring.
have Hsum :
    (ms_view_distinguish_pr (d_ms_after_binding_public_semantic_observable_v2_parameterized x s xms) D -
   ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D) +
  (ms_view_distinguish_pr (d_ms_after_rom_public_semantic_observable_v2_parameterized x s xms) D -
     ms_view_distinguish_pr (d_ms_after_rom_observable_v2 x s xms) D) <=
    (ms_hash_binding_local_public_divergence_upper_mass_parameterized +
     ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized) +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
  exact (ler_add _ _ _ _ Hpublic Hland).
apply (ler_trans _ _ _ Hsum).
have -> :
    (ms_hash_binding_local_public_divergence_upper_mass_parameterized +
     ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized) +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized =
    ms_hash_binding_local_public_divergence_upper_mass_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized +
    ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
  by ring.
by apply lerr.
qed.

lemma A_MS_public_endpoint_parameterized_game_advantage_bound :
  forall (x : qssm_public_input) (s : seed) (xms : ms_public_input)
         (D : distinguisher),
    Adv_ms_public_endpoint_parameterized x s xms D <=
  ms_hash_binding_local_public_divergence_upper_mass_parameterized +
      ParameterizedBudgetParameters.epsilon_ms_rom_programmability_parameterized.
proof.
move=> x s xms D.
rewrite /Adv_ms_public_endpoint_parameterized /game_pr_ms_public_endpoint_core_parameterized.
rewrite /d_ms_public_endpoint_stage_observable_v2_parameterized /=.
exact (A_MS_public_endpoint_parameterized_transition_bound x s xms D).
qed.