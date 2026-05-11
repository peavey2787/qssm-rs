require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import StdOrder.
require import LESurface.
require import LERealExecution.
require import LERejectionSamplerCore.
require import LERejectionSamplerSemanticMarginals.
require ParameterizedBudgetParameters.

(*---*) import RealOrder.

type le_rejection_parameterized_hidden_material =
  LERejectionSamplerCore.le_rejection_shadow_hidden_material.

type le_rejection_parameterized_state =
  LERejectionSamplerCore.le_rejection_shadow_state.

op d_le_rejection_parameterized_real_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  LERejectionSamplerCore.d_le_rejection_real_execution_view x s.

op d_le_rejection_parameterized_branch_choice : bool distr =
  dmap (drange 0 ParameterizedBudgetParameters.le_rej_param_total_count)
    (fun slot : int => slot < ParameterizedBudgetParameters.le_rej_param_failure_count).

op le_rejection_parameterized_local_reject_branch_mass : real =
  mu d_le_rejection_parameterized_branch_choice (fun (reject : bool) => reject).

lemma d_le_rejection_parameterized_branch_choice_lossless :
  is_lossless d_le_rejection_parameterized_branch_choice.
proof.
rewrite /d_le_rejection_parameterized_branch_choice.
apply dmap_ll.
apply drange_ll.
exact ParameterizedBudgetParameters.le_rej_param_total_count_pos.
qed.

lemma le_rejection_parameterized_dmap_dprod_fst_lossless ['a 'b]
  (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
exact LERejectionSamplerCore.le_rejection_shadow_dmap_dprod_fst_lossless.
qed.

lemma le_rejection_parameterized_dmap_dprod_snd_lossless ['a 'b]
  (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
exact LERejectionSamplerCore.le_rejection_shadow_dmap_dprod_snd_lossless.
qed.

lemma d_le_rejection_parameterized_real_execution_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_rejection_parameterized_real_execution_view x s).
proof.
exact (LERejectionSamplerCore.d_le_rejection_real_execution_view_lossless x s).
qed.

op le_rejection_parameterized_reject_event
  (st : le_rejection_parameterized_state) : bool =
  LERejectionSamplerCore.le_rejection_shadow_reject_event st.

op le_rejection_parameterized_branch_image_of_observable
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_transcript_observable =
  LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable
    x s obs reject.

op le_rejection_parameterized_state_of_branch_execution
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_rejection_parameterized_state =
  LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution
    x s obs reject.

op d_le_rejection_parameterized_coupled_state
  (x : qssm_public_input) (s : seed) : le_rejection_parameterized_state distr =
  dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
        d_le_rejection_parameterized_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p)).

op d_le_rejection_parameterized_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_parameterized_coupled_state x s)
    LERejectionSamplerCore.le_rejection_shadow_pre_observable.

op d_le_rejection_parameterized_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_parameterized_coupled_state x s)
    LERejectionSamplerCore.le_rejection_shadow_post_observable.

op d_le_parameterized_post_rejection_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_rejection_parameterized_post_marginal x s.

lemma d_le_rejection_parameterized_pre_marginal_matches_execution_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_parameterized_pre_marginal x s =
    d_le_rejection_parameterized_real_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_parameterized_pre_marginal.
rewrite /d_le_rejection_parameterized_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p))
  LERejectionSamplerCore.le_rejection_shadow_pre_observable
  ((d_le_rejection_parameterized_real_execution_view x s) `*`
   d_le_rejection_parameterized_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
        d_le_rejection_parameterized_branch_choice)
    (LERejectionSamplerCore.le_rejection_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
        d_le_rejection_parameterized_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /LERejectionSamplerCore.le_rejection_shadow_pre_observable /(\o)
    /le_rejection_parameterized_state_of_branch_execution
    /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution.
rewrite Hmap.
exact (le_rejection_parameterized_dmap_dprod_fst_lossless
  (d_le_rejection_parameterized_real_execution_view x s)
  d_le_rejection_parameterized_branch_choice
  d_le_rejection_parameterized_branch_choice_lossless).
qed.

lemma d_le_rejection_parameterized_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_parameterized_post_marginal x s =
      dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
            d_le_rejection_parameterized_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p)).`lers_post_observable).
proof.
move=> x s.
rewrite /d_le_rejection_parameterized_post_marginal.
rewrite /d_le_rejection_parameterized_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p))
  LERejectionSamplerCore.le_rejection_shadow_post_observable
  ((d_le_rejection_parameterized_real_execution_view x s) `*`
   d_le_rejection_parameterized_branch_choice)).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
by rewrite /LERejectionSamplerCore.le_rejection_shadow_post_observable /(\o).
qed.

lemma d_le_rejection_parameterized_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_parameterized_post_marginal x s =
      dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
            d_le_rejection_parameterized_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_rejection_parameterized_branch_image_of_observable x s (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_rejection_parameterized_post_marginal_pairE x s).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
exact (LERejectionSamplerSemanticMarginals.le_rejection_shadow_semantic_post_branch_imageE
  x s obs reject).
qed.

lemma d_le_rejection_parameterized_pre_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_parameterized_pre_marginal x s =
      dmap (dunit false)
        (fun reject =>
          le_rejection_parameterized_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite d_le_rejection_parameterized_pre_marginal_matches_execution_view.
rewrite /d_le_rejection_parameterized_real_execution_view /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit /=.
rewrite /le_rejection_parameterized_branch_image_of_observable.
rewrite /LERejectionSamplerCore.le_rejection_shadow_semantic_branch_image_of_observable.
rewrite (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id
  x s (le_real_execution_observable x s)).
by [].
qed.

lemma d_le_rejection_parameterized_post_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_parameterized_post_marginal x s =
      dmap d_le_rejection_parameterized_branch_choice
        (fun reject =>
          le_rejection_parameterized_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite (d_le_rejection_parameterized_post_marginal_branch_split_pairE x s).
rewrite /d_le_rejection_parameterized_real_execution_view /d_le_real_view /d_le_real_execution_view.
have Hmap :
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_parameterized_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_parameterized_branch_image_of_observable x s (fst p) (snd p)) =
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_parameterized_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_parameterized_branch_image_of_observable x s
        (le_real_execution_observable x s) (snd p)).
  apply eq_dmap_in=> p Hp /=.
  case: p Hp=> obs reject /=.
  rewrite supp_dprod => -[Hobs _].
  move: Hobs; rewrite supp_dunit => ->.
  by [].
rewrite Hmap.
rewrite -(dmap_comp snd
  (fun reject =>
    le_rejection_parameterized_branch_image_of_observable x s
      (le_real_execution_observable x s) reject)
  ((dunit (le_real_execution_observable x s)) `*`
   d_le_rejection_parameterized_branch_choice)).
rewrite (le_rejection_parameterized_dmap_dprod_snd_lossless
  (dunit (le_real_execution_observable x s))
  d_le_rejection_parameterized_branch_choice
  (dunit_ll (le_real_execution_observable x s))).
by [].
qed.

lemma d_le_rejection_parameterized_reject_event_image_branch_choice :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_rejection_parameterized_coupled_state x s)
      le_rejection_parameterized_reject_event =
      d_le_rejection_parameterized_branch_choice.
proof.
move=> x s.
rewrite /d_le_rejection_parameterized_coupled_state.
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p))
  le_rejection_parameterized_reject_event
  ((d_le_rejection_parameterized_real_execution_view x s) `*`
   d_le_rejection_parameterized_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
        d_le_rejection_parameterized_branch_choice)
    (le_rejection_parameterized_reject_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_rejection_parameterized_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_parameterized_real_execution_view x s) `*`
        d_le_rejection_parameterized_branch_choice) snd.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /(\o)
    /le_rejection_parameterized_reject_event
    /le_rejection_parameterized_state_of_branch_execution
    /LERejectionSamplerCore.le_rejection_shadow_semantic_state_of_branch_execution
    (LERejectionSamplerSemanticMarginals.le_rejection_shadow_semantic_reject_event_branch_stateE
      x s obs reject).
rewrite Hmap.
exact (le_rejection_parameterized_dmap_dprod_snd_lossless
  (d_le_rejection_parameterized_real_execution_view x s)
  d_le_rejection_parameterized_branch_choice
  (d_le_rejection_parameterized_real_execution_view_lossless x s)).
qed.