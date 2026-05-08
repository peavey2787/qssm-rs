require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LERealExecution.
require import LERejectionSampler.
require import LESurface.
require LEFsProgrammingCoreDefs.
require import LEFsProgrammingShadowBranch.
require BudgetParameters.

(*---*) import RealOrder.

type le_fs_shadow_state = LEFsProgrammingShadowBranch.le_fs_shadow_state.

op d_le_fs_shadow_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  dmap ((LEFsProgrammingCoreDefs.d_le_pre_fs_programming_view x s) `*`
        LEFsProgrammingShadowBranch.d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      LEFsProgrammingShadowBranch.le_fs_shadow_state_of_branch_observable
        (fst p) (snd p)).

op d_le_fs_shadow_semantic_coupled_state
  (x : qssm_public_input) (s : seed) : le_fs_shadow_state distr =
  dmap ((LEFsProgrammingCoreDefs.d_le_pre_fs_semantic_programming_view x s) `*`
        LEFsProgrammingShadowBranch.d_le_fs_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      LEFsProgrammingShadowBranch.le_fs_shadow_state_of_branch_observable
        (fst p) (snd p)).

op d_le_fs_shadow_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    LEFsProgrammingShadowBranch.le_fs_shadow_pre_observable.

op d_le_fs_shadow_semantic_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_semantic_coupled_state x s)
    LEFsProgrammingShadowBranch.le_fs_shadow_pre_observable.

op d_le_fs_shadow_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_coupled_state x s)
    LEFsProgrammingShadowBranch.le_fs_shadow_post_observable.

op d_le_fs_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_fs_shadow_semantic_coupled_state x s)
    LEFsProgrammingShadowBranch.le_fs_shadow_semantic_post_state_observable.

op d_le_fs_shadow_semantic_good_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LEFsProgrammingCoreDefs.d_le_post_fs_semantic_programmed_view x s.

op d_le_fs_shadow_semantic_bad_branch_image
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (LEFsProgrammingCoreDefs.d_le_pre_fs_semantic_programming_view x s)
    LEFsProgrammingShadowBranch.le_fs_shadow_semantic_programmed_view_of_observable.