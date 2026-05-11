require import QssmTypes.
require import Real.
require import SDist.
require import LESurface.
require import LEFsProgrammingFailureProbabilityParameterized.
require import LEFsProgrammingLiveParameterizedCore.
require import LEFsProgrammingLiveParameterizedMass.
require ParameterizedBudgetParameters.

(* Parallel theorem-facing LE FS parameterized bridge.
   This now forwards to the live parameterized FS branch/mass lane rather than
   comparing the demo FS bad-branch mass against the parameterized owner. *)

lemma A_LE_fs_semantic_programming_sampler_sdist_le_parameterized_budget :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_fs_programming_hiding_bound x s D =>
    sdist (d_le_parameterized_post_fs_semantic_programmed_view x s)
      (d_le_fs_parameterized_shadow_semantic_post_marginal x s)
      <= ParameterizedBudgetParameters.epsilon_le_fs_parameterized.
proof.
move=> x s D _ _ _.
rewrite sdistC.
exact (A_LE_fs_parameterized_shadow_semantic_post_marginal_sdist_le_parameterized_budget x s).
qed.