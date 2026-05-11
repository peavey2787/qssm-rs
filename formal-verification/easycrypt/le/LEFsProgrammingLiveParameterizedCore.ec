require import QssmTypes.
require import AllCore Distr.
require import Real.
require import StdOrder.
require import LESurface.
require import LERejectionSamplerParameterizedCore.
require import LEFsProgrammingSurface.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

(* Live parameterized FS branch/midpoint core.
   This reuses the existing FS surrogate and semantic branch-image operators,
   but swaps the bad-branch sampler to the parameterized owner surface and
   consumes the already-live parameterized rejection midpoint. *)

op d_le_fs_parameterized_shadow_branch_choice : bool distr =
  dmap (drange 0 ParameterizedBudgetParameters.le_fs_param_total_count)
    (fun slot : int => slot < ParameterizedBudgetParameters.le_fs_param_failure_count).

lemma d_le_fs_parameterized_shadow_branch_choice_lossless :
  is_lossless d_le_fs_parameterized_shadow_branch_choice.
proof.
rewrite /d_le_fs_parameterized_shadow_branch_choice.
apply dmap_ll.
apply drange_ll.
exact ParameterizedBudgetParameters.le_fs_param_total_count_pos.
qed.

op d_le_parameterized_pre_fs_semantic_programming_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LERejectionSamplerParameterizedCore.d_le_parameterized_post_rejection_view x s.

op d_le_parameterized_post_fs_semantic_programmed_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_parameterized_pre_fs_semantic_programming_view x s)
    LEFsProgrammingSurface.le_fs_surrogate_transform.

op d_le_fs_parameterized_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap ((d_le_parameterized_pre_fs_semantic_programming_view x s) `*`
        d_le_fs_parameterized_shadow_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
        (fst p) (snd p)).

lemma d_le_parameterized_post_fs_semantic_programmed_view_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_parameterized_post_fs_semantic_programmed_view x s =
      dmap ((d_le_parameterized_pre_fs_semantic_programming_view x s) `*`
            dunit false)
        (fun (p : le_transcript_observable * bool) =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
            (fst p) (snd p)).
proof.
move=> x s.
rewrite /d_le_parameterized_post_fs_semantic_programmed_view.
rewrite dmap_dprodE.
have -> :
    dlet (d_le_parameterized_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit false)
        (fun bad =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad)) =
    dlet (d_le_parameterized_pre_fs_semantic_programming_view x s)
      (fun obs => dmap (dunit obs)
        (fun (obs' : le_transcript_observable) =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
            obs' false)).
  apply (in_eq_dlet
    (fun obs => dmap (dunit false)
      (fun bad =>
        LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable obs bad))
    (fun obs => dmap (dunit obs)
      (fun (obs' : le_transcript_observable) =>
        LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
          obs' false))
    (d_le_parameterized_pre_fs_semantic_programming_view x s)).
  move=> obs _ /=.
  rewrite !dmap_dunit /=.
  by rewrite /LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable.
rewrite -dmap_dlet.
rewrite dlet_d_unit.
by [].
qed.

lemma d_le_fs_parameterized_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_fs_parameterized_shadow_semantic_post_marginal x s =
      dmap ((d_le_parameterized_pre_fs_semantic_programming_view x s) `*`
            d_le_fs_parameterized_shadow_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          LEFsProgrammingSurface.le_fs_shadow_semantic_branch_image_of_observable
            (fst p) (snd p)).
proof.
by move=> x s; rewrite /d_le_fs_parameterized_shadow_semantic_post_marginal.
qed.