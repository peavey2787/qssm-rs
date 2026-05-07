require import QssmTypes.
require import AllCore Distr.
require import List.
require import Real.
require import SDist.
require import StdOrder.
require import LESurface.
require import LERealExecution.
require BudgetParameters.

(*---*) import RealOrder.

(* Lower execution-facing rejection sampler boundary below `LERejection.ec`.
   This file introduces the sampler surface needed to eventually discharge the
   rejection-side sdist theorem without adding a new quantitative axiom. *)

type le_rejection_shadow_hidden_material = {
  lershm_challenge_seed_material : le_real_execution_challenge_seed_material;
  lershm_resampled_observable : le_transcript_observable;
}.

type le_rejection_shadow_state = {
  lers_pre_observable : le_transcript_observable;
  lers_post_observable : le_transcript_observable;
  lers_accepts : bool;
  lers_hidden_material : le_rejection_shadow_hidden_material;
}.

op d_le_rejection_real_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_real_view x s.

op le_rejection_transform
  (obs : le_transcript_observable) : le_transcript_observable =
  le_post_rejection_surrogate obs.

(* Shadow coupled rejection lane.

   This lane is intentionally separate from the active theorem path. It adds
   the lower state shape needed for a future non-identity rejection sampler,
   while the current checked model still closes the rejection step by exact
   equality. The acceptance bit is now derived from concrete lower execution
   material (`lerecsm_branch` in `LERealExecution.ec`), and the hidden material
   explicitly carries both that challenge-seed material and the resampled
   observable. Later refinements can replace the current branch-fixed carrier
   with a genuine rejection-side sampler without rewiring the theorem-facing
   names first. *)
op le_rejection_shadow_hidden_material_of_execution
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  le_rejection_shadow_hidden_material =
  {| lershm_challenge_seed_material =
       le_real_execution_challenge_seed_material_of x s;
     lershm_resampled_observable = le_rejection_transform obs |}.

op le_rejection_shadow_accepts_from_hidden_material
  (hm : le_rejection_shadow_hidden_material) : bool =
  if hm.`lershm_challenge_seed_material.`lerecsm_branch then false else true.

op le_rejection_shadow_post_of_execution
  (obs : le_transcript_observable) (hm : le_rejection_shadow_hidden_material) :
  le_transcript_observable =
  if le_rejection_shadow_accepts_from_hidden_material hm
  then obs
  else hm.`lershm_resampled_observable.

op le_rejection_shadow_state_of_execution
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  le_rejection_shadow_state =
  let hm = le_rejection_shadow_hidden_material_of_execution x s obs in
  {| lers_pre_observable = obs;
     lers_post_observable = le_rejection_shadow_post_of_execution obs hm;
     lers_accepts = le_rejection_shadow_accepts_from_hidden_material hm;
     lers_hidden_material = hm |}.

op le_rejection_shadow_pre_observable
  (st : le_rejection_shadow_state) : le_transcript_observable =
  st.`lers_pre_observable.

op le_rejection_shadow_post_observable
  (st : le_rejection_shadow_state) : le_transcript_observable =
  st.`lers_post_observable.

op le_rejection_shadow_accept_event
  (st : le_rejection_shadow_state) : bool =
  st.`lers_accepts.

op le_rejection_shadow_reject_event
  (st : le_rejection_shadow_state) : bool =
  if st.`lers_accepts then false else true.

op d_le_rejection_shadow_coupled_state
  (x : qssm_public_input) (s : seed) : le_rejection_shadow_state distr =
  dmap (d_le_rejection_real_execution_view x s)
    (le_rejection_shadow_state_of_execution x s).

op d_le_rejection_shadow_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_shadow_coupled_state x s)
    le_rejection_shadow_pre_observable.

op d_le_rejection_shadow_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_shadow_coupled_state x s)
    le_rejection_shadow_post_observable.

op le_rejection_shadow_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (d_le_rejection_shadow_coupled_state x s)
    le_rejection_shadow_reject_event.

op d_le_rejection_post_execution_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_real_execution_view x s) le_rejection_transform.

op le_rejection_shadow_semantic_branch_support : bool list =
  LERealExecution.le_real_execution_semantic_rejection_branch_support.

op d_le_rejection_shadow_semantic_branch_choice : bool distr =
  LERealExecution.d_le_real_execution_semantic_rejection_branch_choice.

op le_rejection_shadow_semantic_local_reject_branch_mass : real =
  mu d_le_rejection_shadow_semantic_branch_choice (fun (reject : bool) => reject).

lemma le_rejection_shadow_semantic_branch_choice_lossless :
  is_lossless d_le_rejection_shadow_semantic_branch_choice.
proof.
rewrite /d_le_rejection_shadow_semantic_branch_choice.
exact LERealExecution.le_real_execution_semantic_rejection_branch_choice_lossless.
qed.

lemma le_rejection_shadow_semantic_accept_branch_has_support :
  false \in d_le_rejection_shadow_semantic_branch_choice.
proof.
rewrite /d_le_rejection_shadow_semantic_branch_choice.
exact LERealExecution.le_real_execution_semantic_rejection_accept_branch_has_support.
qed.

lemma le_rejection_shadow_semantic_reject_branch_has_support :
  true \in d_le_rejection_shadow_semantic_branch_choice.
proof.
rewrite /d_le_rejection_shadow_semantic_branch_choice.
exact LERealExecution.le_real_execution_semantic_rejection_reject_branch_has_support.
qed.

lemma le_rejection_shadow_semantic_branch_choice_mass_false :
  mu1 d_le_rejection_shadow_semantic_branch_choice false =
  (BudgetParameters.le_rejection_semantic_total_slot_count -
   BudgetParameters.le_rejection_semantic_reject_slot_count)%r /
  BudgetParameters.le_rejection_semantic_total_slot_count%r.
proof.
rewrite /d_le_rejection_shadow_semantic_branch_choice.
exact LERealExecution.le_real_execution_semantic_rejection_branch_choice_mass_false.
qed.

lemma le_rejection_shadow_semantic_branch_choice_mass_true :
  mu1 d_le_rejection_shadow_semantic_branch_choice true =
  BudgetParameters.le_rejection_semantic_reject_slot_count%r /
  BudgetParameters.le_rejection_semantic_total_slot_count%r.
proof.
rewrite /d_le_rejection_shadow_semantic_branch_choice.
exact LERealExecution.le_real_execution_semantic_rejection_branch_choice_mass_true.
qed.

lemma le_rejection_shadow_semantic_local_reject_branch_mass_is_true_mass :
  le_rejection_shadow_semantic_local_reject_branch_mass =
  mu1 d_le_rejection_shadow_semantic_branch_choice true.
proof.
rewrite /le_rejection_shadow_semantic_local_reject_branch_mass.
have Hmu1 :
    mu d_le_rejection_shadow_semantic_branch_choice (fun (reject : bool) => reject) =
    mu1 d_le_rejection_shadow_semantic_branch_choice true.
  apply/mu_eq=> reject /=.
  by case: reject.
exact Hmu1.
qed.

lemma le_rejection_shadow_semantic_local_reject_branch_mass_closed_form :
  le_rejection_shadow_semantic_local_reject_branch_mass =
  BudgetParameters.le_rejection_semantic_reject_slot_count%r /
  BudgetParameters.le_rejection_semantic_total_slot_count%r.
proof.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_is_true_mass.
exact le_rejection_shadow_semantic_branch_choice_mass_true.
qed.

lemma le_rejection_shadow_semantic_local_reject_branch_mass_eq_epsilon :
  le_rejection_shadow_semantic_local_reject_branch_mass =
  BudgetParameters.epsilon_le_rej_semantic.
proof.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
rewrite BudgetParameters.epsilon_le_rej_semantic_closed_form.
by [].
qed.

op le_rejection_shadow_semantic_challenge_seed_material_of_execution
  (x : qssm_public_input) (s : seed) (reject : bool) :
  le_real_execution_challenge_seed_material =
  LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch
    x s reject.

op le_rejection_shadow_semantic_programmed_query_digest_material_of_execution
  (x : qssm_public_input) (s : seed) (reject : bool) :
  le_real_execution_programmed_query_digest_material =
  LERealExecution.le_real_execution_semantic_rejection_programmed_query_digest_material_of_branch
    x s reject.

op le_rejection_shadow_semantic_primitive_material_of_observable_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_real_execution_primitive_material =
  LERealExecution.le_real_execution_semantic_rejection_primitive_material_of_observable_branch
    x s obs reject.

op le_rejection_shadow_semantic_branch_image_of_observable
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_transcript_observable =
  LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch
    x s obs reject.

op le_rejection_shadow_semantic_hidden_material_of_execution_branch
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_rejection_shadow_hidden_material =
  {| lershm_challenge_seed_material =
       le_rejection_shadow_semantic_challenge_seed_material_of_execution x s reject;
     lershm_resampled_observable =
       le_rejection_shadow_semantic_branch_image_of_observable x s obs reject |}.

op le_rejection_shadow_semantic_state_of_branch_execution
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) : le_rejection_shadow_state =
  let hm =
    le_rejection_shadow_semantic_hidden_material_of_execution_branch x s obs reject in
  {| lers_pre_observable = obs;
     lers_post_observable = le_rejection_shadow_post_of_execution obs hm;
     lers_accepts = le_rejection_shadow_accepts_from_hidden_material hm;
     lers_hidden_material = hm |}.

op d_le_rejection_shadow_semantic_coupled_state
  (x : qssm_public_input) (s : seed) : le_rejection_shadow_state distr =
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p)).

op d_le_rejection_shadow_semantic_pre_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_shadow_semantic_coupled_state x s)
    le_rejection_shadow_pre_observable.

op d_le_rejection_shadow_semantic_post_marginal
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  dmap (d_le_rejection_shadow_semantic_coupled_state x s)
    le_rejection_shadow_post_observable.

op d_le_semantic_post_rejection_view
  (x : qssm_public_input) (s : seed) : le_transcript_observable distr =
  d_le_rejection_shadow_semantic_post_marginal x s.

op le_rejection_shadow_semantic_failure_probability
  (x : qssm_public_input) (s : seed) =
  mu (dmap (d_le_rejection_shadow_semantic_coupled_state x s)
       le_rejection_shadow_reject_event)
    (fun (reject : bool) => reject).

op le_rejection_shadow_semantic_ticket_failure_probability
  (x : qssm_public_input) (s : seed) : real =
  LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability x s.

lemma le_rejection_shadow_dmap_dprod_fst_lossless ['a 'b]
  (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
rewrite (dprod_marginalL da db (fun (a : 'a) => a)).
rewrite dmap_id.
have Hw : weight db = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma le_rejection_shadow_dmap_dprod_snd_lossless ['a 'b]
  (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw : weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma d_le_rejection_real_execution_view_lossless
  (x : qssm_public_input) (s : seed) :
  is_lossless (d_le_rejection_real_execution_view x s).
proof.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
exact (dunit_ll (le_real_execution_observable x s)).
qed.

lemma le_real_execution_observable_in_rejection_execution_view
  (x : qssm_public_input) (s : seed) :
  le_real_execution_observable x s \in d_le_rejection_real_execution_view x s.
proof.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
by rewrite supp_dunit.
qed.

lemma le_rejection_shadow_semantic_post_branch_imageE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  (le_rejection_shadow_semantic_state_of_branch_execution x s obs reject).`lers_post_observable =
  le_rejection_shadow_semantic_branch_image_of_observable x s obs reject.
proof.
case: reject=> /=.
  rewrite /le_rejection_shadow_semantic_state_of_branch_execution.
  rewrite /le_rejection_shadow_post_of_execution.
  rewrite /le_rejection_shadow_semantic_hidden_material_of_execution_branch.
  rewrite /le_rejection_shadow_accepts_from_hidden_material.
  rewrite /le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch.
  rewrite /le_rejection_shadow_semantic_branch_image_of_observable.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch /=.
  by [].
case: obs=> ccoeffs tcoeffs zcoeffs cseed pqdig qmat payload /=.
case: qmat=> rowseed rowdig respdig log badflag /=.
rewrite /le_rejection_shadow_semantic_state_of_branch_execution.
rewrite /le_rejection_shadow_post_of_execution.
rewrite /le_rejection_shadow_semantic_hidden_material_of_execution_branch.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch.
rewrite /le_rejection_shadow_semantic_branch_image_of_observable.
rewrite /LERealExecution.le_real_execution_semantic_rejection_observable_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_ticket_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_primitive_material_of_observable_ticket /=.
rewrite /LERealExecution.le_real_execution_challenge_seed_obs_of_material.
rewrite /LERealExecution.le_real_execution_programmed_query_digest_obs_of_material.
rewrite /LERealExecution.le_real_execution_semantic_rejection_repaired_query_material_of_observable_branch /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_obs_of_branch.
rewrite /LERealExecution.le_real_execution_semantic_rejection_programmed_query_digest_obs_of_branch /=.
by [].
qed.

lemma le_rejection_shadow_semantic_reject_event_branch_stateE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  le_rejection_shadow_reject_event
    (le_rejection_shadow_semantic_state_of_branch_execution x s obs reject) = reject.
proof.
case: reject.
  rewrite /le_rejection_shadow_reject_event.
  rewrite /le_rejection_shadow_semantic_state_of_branch_execution /=.
  rewrite /le_rejection_shadow_accepts_from_hidden_material.
  rewrite /le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
  rewrite /le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
  rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
  by [].
rewrite /le_rejection_shadow_reject_event.
rewrite /le_rejection_shadow_semantic_state_of_branch_execution /=.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_rejection_shadow_semantic_hidden_material_of_execution_branch /=.
rewrite /le_rejection_shadow_semantic_challenge_seed_material_of_execution /=.
rewrite /LERealExecution.le_real_execution_semantic_rejection_challenge_seed_material_of_branch /=.
by [].
qed.

lemma le_rejection_shadow_semantic_reject_event_of_categoryE
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (category : BudgetParameters.le_rejection_semantic_ticket_category) :
  le_rejection_shadow_reject_event
    (le_rejection_shadow_semantic_state_of_branch_execution x s obs
      (LERealExecution.le_real_execution_semantic_rejection_decision_reject
        (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
          category))) =
  BudgetParameters.le_rejection_semantic_ticket_category_is_failure category.
proof.
rewrite (le_rejection_shadow_semantic_reject_event_branch_stateE x s obs
  (LERealExecution.le_real_execution_semantic_rejection_decision_reject
    (LERealExecution.le_real_execution_semantic_rejection_decision_of_category
      category))).
exact
  (LERealExecution.le_real_execution_semantic_rejection_decision_of_category_rejectE
    category).
qed.

lemma d_le_rejection_shadow_semantic_coupled_state_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_coupled_state x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p)).
proof.
by move=> x s; rewrite /d_le_rejection_shadow_semantic_coupled_state.
qed.

lemma le_rejection_shadow_semantic_branch_state_has_support
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable)
  (reject : bool) :
  obs \in d_le_rejection_real_execution_view x s =>
  reject \in d_le_rejection_shadow_semantic_branch_choice =>
  le_rejection_shadow_semantic_state_of_branch_execution x s obs reject
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
move=> Hobs Hreject.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite supp_dmap.
exists (obs, reject); split.
  by rewrite supp_dprod Hobs Hreject.
by [].
qed.

lemma le_rejection_shadow_semantic_accept_branch_support
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_state_of_branch_execution x s
    (le_real_execution_observable x s) false
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
apply (le_rejection_shadow_semantic_branch_state_has_support x s
  (le_real_execution_observable x s) false).
  exact (le_real_execution_observable_in_rejection_execution_view x s).
exact le_rejection_shadow_semantic_accept_branch_has_support.
qed.

lemma le_rejection_shadow_semantic_reject_branch_support
  (x : qssm_public_input) (s : seed) :
  le_rejection_shadow_semantic_state_of_branch_execution x s
    (le_real_execution_observable x s) true
    \in d_le_rejection_shadow_semantic_coupled_state x s.
proof.
apply (le_rejection_shadow_semantic_branch_state_has_support x s
  (le_real_execution_observable x s) true).
  exact (le_real_execution_observable_in_rejection_execution_view x s).
exact le_rejection_shadow_semantic_reject_branch_has_support.
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s =
    d_le_rejection_real_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_shadow_semantic_pre_marginal.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  le_rejection_shadow_pre_observable
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (le_rejection_shadow_pre_observable \o
      (fun (p : le_transcript_observable * bool) =>
        le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice) fst.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /le_rejection_shadow_pre_observable /(\o)
    /le_rejection_shadow_semantic_state_of_branch_execution.
rewrite Hmap.
exact (le_rejection_shadow_dmap_dprod_fst_lossless
  (d_le_rejection_real_execution_view x s)
  d_le_rejection_shadow_semantic_branch_choice
  le_rejection_shadow_semantic_branch_choice_lossless).
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_matches_real_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s = d_le_real_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view.
by rewrite /d_le_rejection_real_execution_view.
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          (le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p)).`lers_post_observable).
proof.
move=> x s.
rewrite /d_le_rejection_shadow_semantic_post_marginal.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  le_rejection_shadow_post_observable
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
by rewrite /le_rejection_shadow_post_observable /(\o).
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_branch_split_pairE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap ((d_le_rejection_real_execution_view x s) `*`
            d_le_rejection_shadow_semantic_branch_choice)
        (fun (p : le_transcript_observable * bool) =>
          le_rejection_shadow_semantic_branch_image_of_observable x s (fst p) (snd p)).
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_post_marginal_pairE x s).
apply eq_dmap_in=> p _ /=.
case: p=> obs reject /=.
exact (le_rejection_shadow_semantic_post_branch_imageE x s obs reject).
qed.

lemma d_le_rejection_shadow_semantic_pre_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_pre_marginal x s =
      dmap (dunit false)
        (fun reject =>
          le_rejection_shadow_semantic_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite d_le_rejection_shadow_semantic_pre_marginal_matches_execution_view.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit /=.
rewrite /le_rejection_shadow_semantic_branch_image_of_observable.
rewrite (LERealExecution.le_real_execution_semantic_rejection_accept_branch_id
  x s (le_real_execution_observable x s)).
by [].
qed.

lemma d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_semantic_post_marginal x s =
      dmap d_le_rejection_shadow_semantic_branch_choice
        (fun reject =>
          le_rejection_shadow_semantic_branch_image_of_observable x s
            (le_real_execution_observable x s) reject).
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_post_marginal_branch_split_pairE x s).
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
have Hmap :
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_shadow_semantic_branch_image_of_observable x s (fst p) (snd p)) =
  dmap ((dunit (le_real_execution_observable x s)) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (fun (p : le_transcript_observable * bool) =>
      le_rejection_shadow_semantic_branch_image_of_observable x s
        (le_real_execution_observable x s) (snd p)).
  apply eq_dmap_in=> p Hp /=.
  case: p Hp=> obs reject /=.
  rewrite supp_dprod => -[Hobs _].
  move: Hobs; rewrite supp_dunit => ->.
  by [].
rewrite Hmap.
rewrite -(dmap_comp snd
  (fun reject =>
    le_rejection_shadow_semantic_branch_image_of_observable x s
      (le_real_execution_observable x s) reject)
  ((dunit (le_real_execution_observable x s)) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
rewrite (le_rejection_shadow_dmap_dprod_snd_lossless
  (dunit (le_real_execution_observable x s))
  d_le_rejection_shadow_semantic_branch_choice
  (dunit_ll (le_real_execution_observable x s))).
by [].
qed.

lemma le_rejection_shadow_semantic_branch_choice_sdist_dunit_false_le_reject_branch_mass :
  sdist d_le_rejection_shadow_semantic_branch_choice (dunit false) <=
  le_rejection_shadow_semantic_local_reject_branch_mass.
proof.
apply sdist_le_ub=> E.
rewrite dunitE.
case (E false) => [Ef|Ef] /=.
  case (E true) => [Et|Et] /=.
    have HE :
        mu d_le_rejection_shadow_semantic_branch_choice E =
        mu d_le_rejection_shadow_semantic_branch_choice predT.
      apply/mu_eq=> reject /=.
      by case: reject=> /=; rewrite ?Ef ?Et.
    have Hw : weight d_le_rejection_shadow_semantic_branch_choice = 1%r.
      exact (is_losslessP _ le_rejection_shadow_semantic_branch_choice_lossless).
    rewrite HE /weight Hw.
    by smt().
  have HE :
      mu d_le_rejection_shadow_semantic_branch_choice E =
      mu1 d_le_rejection_shadow_semantic_branch_choice false.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE le_rejection_shadow_semantic_branch_choice_mass_false.
  rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
  by smt().
case (E true) => [Et|Et] /=.
  have HE :
      mu d_le_rejection_shadow_semantic_branch_choice E =
      mu1 d_le_rejection_shadow_semantic_branch_choice true.
    apply/mu_eq=> reject /=.
    by case: reject=> /=; rewrite ?Ef ?Et.
  rewrite HE le_rejection_shadow_semantic_branch_choice_mass_true.
  rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
  by smt().
have HE :
    mu d_le_rejection_shadow_semantic_branch_choice E =
    mu d_le_rejection_shadow_semantic_branch_choice pred0.
  apply/mu_eq=> reject /=.
  by case: reject=> /=; rewrite ?Ef ?Et.
rewrite HE mu0.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_closed_form.
by smt().
qed.

lemma d_le_rejection_shadow_semantic_reject_event_image_branch_choice :
  forall (x : qssm_public_input) (s : seed),
    dmap (d_le_rejection_shadow_semantic_coupled_state x s)
      le_rejection_shadow_reject_event =
      d_le_rejection_shadow_semantic_branch_choice.
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_coupled_state_pairE x s).
rewrite (dmap_comp (fun (p : le_transcript_observable * bool) =>
    le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))
  le_rejection_shadow_reject_event
  ((d_le_rejection_real_execution_view x s) `*`
   d_le_rejection_shadow_semantic_branch_choice)).
have Hmap :
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice)
    (le_rejection_shadow_reject_event \o
      (fun (p : le_transcript_observable * bool) =>
        le_rejection_shadow_semantic_state_of_branch_execution x s (fst p) (snd p))) =
  dmap ((d_le_rejection_real_execution_view x s) `*`
        d_le_rejection_shadow_semantic_branch_choice) snd.
  apply eq_dmap_in=> p _ /=.
  case: p=> obs reject /=.
  by rewrite /(\o) (le_rejection_shadow_semantic_reject_event_branch_stateE x s obs reject).
rewrite Hmap.
exact (le_rejection_shadow_dmap_dprod_snd_lossless
  (d_le_rejection_real_execution_view x s)
  d_le_rejection_shadow_semantic_branch_choice
  (d_le_rejection_real_execution_view_lossless x s)).
qed.

lemma le_rejection_shadow_semantic_failure_probability_exact_branch_mass :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    le_rejection_shadow_semantic_local_reject_branch_mass.
proof.
move=> x s.
rewrite /le_rejection_shadow_semantic_failure_probability.
rewrite /le_rejection_shadow_semantic_local_reject_branch_mass.
rewrite (d_le_rejection_shadow_semantic_reject_event_image_branch_choice x s).
by [].
qed.

lemma le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_ticket_failure_probability x s =
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite /le_rejection_shadow_semantic_ticket_failure_probability.
exact (LERealExecution.le_real_execution_semantic_rejection_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    le_rejection_shadow_semantic_ticket_failure_probability x s.
proof.
move=> x s.
rewrite le_rejection_shadow_semantic_failure_probability_exact_branch_mass.
rewrite le_rejection_shadow_semantic_local_reject_branch_mass_eq_epsilon.
rewrite -(le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
by [].
qed.

lemma le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s =
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_ticket_failure_probability x s).
exact (le_rejection_shadow_semantic_ticket_failure_probability_eq_epsilon_le_rej_semantic x s).
qed.

lemma A_LE_rejection_shadow_semantic_failure_probability_le_semantic_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_semantic_failure_probability x s <=
    BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_semantic_failure_probability_eq_epsilon_le_rej_semantic x s).
by [].
qed.

lemma A_LE_rejection_shadow_semantic_post_marginal_sdist_le_failure_probability :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_shadow_semantic_pre_marginal x s)
      (d_le_rejection_shadow_semantic_post_marginal x s)
      <= le_rejection_shadow_semantic_failure_probability x s.
proof.
move=> x s.
rewrite (d_le_rejection_shadow_semantic_pre_marginal_fixed_branch_imageE x s).
rewrite (d_le_rejection_shadow_semantic_post_marginal_fixed_branch_imageE x s).
pose F := fun reject =>
  le_rejection_shadow_semantic_branch_image_of_observable x s
    (le_real_execution_observable x s) reject.
have Hmap :
  sdist (dmap (dunit false) F)
    (dmap d_le_rejection_shadow_semantic_branch_choice F) <=
  sdist (dunit false) d_le_rejection_shadow_semantic_branch_choice.
  exact (sdist_dmap (dunit false) d_le_rejection_shadow_semantic_branch_choice F).
apply (ler_trans _ _ _ Hmap).
rewrite sdistC.
apply (ler_trans _ _ _
  le_rejection_shadow_semantic_branch_choice_sdist_dunit_false_le_reject_branch_mass).
rewrite le_rejection_shadow_semantic_failure_probability_exact_branch_mass.
by [].
qed.

lemma A_LE_rejection_shadow_semantic_post_marginal_sdist_le_budget :
  forall (x : qssm_public_input) (s : seed),
    sdist (d_le_rejection_shadow_semantic_pre_marginal x s)
      (d_le_rejection_shadow_semantic_post_marginal x s)
      <= BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
have Hsdist :=
  A_LE_rejection_shadow_semantic_post_marginal_sdist_le_failure_probability x s.
have Hbudget :=
  A_LE_rejection_shadow_semantic_failure_probability_le_semantic_budget x s.
by smt().
qed.

lemma le_rejection_shadow_accepts_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_rejection_shadow_state_of_execution x s obs).`lers_accepts = true.
proof.
rewrite /le_rejection_shadow_state_of_execution.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_rejection_shadow_hidden_material_of_execution.
by rewrite /le_real_execution_challenge_seed_material_of /=.
qed.

lemma le_rejection_shadow_post_of_execution_matches_transform
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  (le_rejection_shadow_state_of_execution x s obs).`lers_post_observable =
  le_rejection_transform obs.
proof.
rewrite /le_rejection_shadow_state_of_execution.
rewrite /le_rejection_shadow_post_of_execution.
rewrite /le_rejection_shadow_hidden_material_of_execution.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_real_execution_challenge_seed_material_of /=.
by rewrite /le_rejection_transform /le_post_rejection_surrogate.
qed.

lemma le_rejection_shadow_reject_event_current_model
  (x : qssm_public_input) (s : seed) (obs : le_transcript_observable) :
  le_rejection_shadow_reject_event (le_rejection_shadow_state_of_execution x s obs) = false.
proof.
rewrite /le_rejection_shadow_reject_event.
by rewrite (le_rejection_shadow_accepts_current_model x s obs).
qed.

lemma d_le_rejection_shadow_pre_marginal_matches_execution_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_rejection_real_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_shadow_pre_marginal /d_le_rejection_shadow_coupled_state.
rewrite (dmap_comp (le_rejection_shadow_state_of_execution x s)
  le_rejection_shadow_pre_observable
  (d_le_rejection_real_execution_view x s)).
have Hmap :
  dmap (d_le_rejection_real_execution_view x s)
    (le_rejection_shadow_pre_observable \o (le_rejection_shadow_state_of_execution x s)) =
  dmap (d_le_rejection_real_execution_view x s)
    (fun (obs : le_transcript_observable) => obs).
- apply eq_dmap_in=> obs _ /=.
  by rewrite /le_rejection_shadow_pre_observable /le_rejection_shadow_state_of_execution /(\o).
rewrite Hmap.
by rewrite dmap_id.
qed.

lemma d_le_rejection_shadow_post_marginal_matches_execution_transform :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_post_marginal x s = d_le_rejection_post_execution_view x s.
proof.
move=> x s.
rewrite /d_le_rejection_shadow_post_marginal /d_le_rejection_shadow_coupled_state.
rewrite (dmap_comp (le_rejection_shadow_state_of_execution x s)
  le_rejection_shadow_post_observable
  (d_le_rejection_real_execution_view x s)).
have Hmap :
  dmap (d_le_rejection_real_execution_view x s)
    (le_rejection_shadow_post_observable \o (le_rejection_shadow_state_of_execution x s)) =
  dmap (d_le_rejection_real_execution_view x s)
    le_rejection_transform.
- apply eq_dmap_in=> obs _ /=.
  rewrite /le_rejection_shadow_post_observable /(\o).
  exact (le_rejection_shadow_post_of_execution_matches_transform x s obs).
rewrite Hmap.
by rewrite /d_le_rejection_post_execution_view.
qed.

lemma d_le_rejection_shadow_pre_post_marginals_equal :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_rejection_shadow_post_marginal x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_pre_marginal_matches_execution_view.
rewrite d_le_rejection_shadow_post_marginal_matches_execution_transform.
by rewrite /d_le_rejection_post_execution_view /d_le_rejection_real_execution_view
  /le_rejection_transform /le_post_rejection_surrogate dmap_id.
qed.

lemma le_rejection_shadow_failure_probability_zero :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_failure_probability x s = 0%r.
proof.
move=> x s.
rewrite /le_rejection_shadow_failure_probability /d_le_rejection_shadow_coupled_state.
rewrite /d_le_rejection_real_execution_view /d_le_real_view /d_le_real_execution_view.
rewrite dmap_dunit dunitE /=.
rewrite /le_rejection_shadow_reject_event.
rewrite /le_rejection_shadow_state_of_execution.
rewrite /le_rejection_shadow_accepts_from_hidden_material.
rewrite /le_rejection_shadow_hidden_material_of_execution.
rewrite /le_real_execution_challenge_seed_material_of /=.
by [].
qed.

lemma A_LE_rejection_shadow_failure_probability_le_semantic_budget :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_shadow_failure_probability x s <= BudgetParameters.epsilon_le_rej_semantic.
proof.
move=> x s.
rewrite (le_rejection_shadow_failure_probability_zero x s).
rewrite /BudgetParameters.epsilon_le_rej_semantic.
by [].
qed.

lemma le_real_view_matches_rejection_execution :
  forall (x : qssm_public_input) (s : seed),
    d_le_real_view x s = d_le_rejection_real_execution_view x s.
proof.
by move=> x s; rewrite /d_le_rejection_real_execution_view.
qed.

lemma d_le_rejection_shadow_pre_marginal_matches_real_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_pre_marginal x s = d_le_real_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_pre_marginal_matches_execution_view.
exact (le_real_view_matches_rejection_execution x s).
qed.

lemma le_post_rejection_view_matches_execution_transform :
  forall (x : qssm_public_input) (s : seed),
    d_le_post_rejection_view x s = d_le_rejection_post_execution_view x s.
proof.
move=> x s.
rewrite /d_le_post_rejection_view /d_le_rejection_post_execution_view.
rewrite /d_le_rejection_real_execution_view /le_rejection_transform.
by [].
qed.

lemma d_le_rejection_shadow_post_marginal_matches_post_rejection_view :
  forall (x : qssm_public_input) (s : seed),
    d_le_rejection_shadow_post_marginal x s = d_le_post_rejection_view x s.
proof.
move=> x s.
rewrite d_le_rejection_shadow_post_marginal_matches_execution_transform.
by rewrite -(le_post_rejection_view_matches_execution_transform x s).
qed.

(* Intended bridge targets from the lower rejection sampler surface to the
   current LE facade.

   The shadow coupled-state lane above now exposes the future non-identity
   insertion points explicitly:

   - `le_rejection_shadow_state`
   - `d_le_rejection_shadow_coupled_state`
   - `d_le_rejection_shadow_pre_marginal`
   - `d_le_rejection_shadow_post_marginal`
   - `le_rejection_shadow_failure_probability`

   The active theorem path does not depend on these names yet. The intended
   future lower theorems on that shadow lane are:

   lemma A_LE_rejection_shadow_sdist_le_failure_probability :
     forall (x : qssm_public_input) (s : seed),
       sdist (d_le_rejection_shadow_pre_marginal x s)
             (d_le_rejection_shadow_post_marginal x s)
         <= le_rejection_shadow_failure_probability x s.

   lemma A_LE_rejection_shadow_failure_probability_le_budget :
     forall (x : qssm_public_input) (s : seed),
       le_rejection_shadow_failure_probability x s <= epsilon_le_rej.

   lemma A_LE_rejection_shadow_failure_probability_le_semantic_budget :
     forall (x : qssm_public_input) (s : seed),
       le_rejection_shadow_failure_probability x s <= epsilon_le_rej_semantic.

   The theorem-facing surfaces above this file now split into an exact-zero
   route and a semantic route:

   lemma A_LE_rejection_sampler_semantic_sdist_le_failure_probability :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= le_rejection_shadow_failure_probability x s.

   lemma A_LE_rejection_sampler_semantic_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= epsilon_le_rej_semantic.

   lemma A_LE_rejection_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= epsilon_le_rej.

   The two bridge lemmas keep the theorem-facing statement on the current
   facade, while the lower sampler surface here carries the concrete execution
   law and transform that must eventually justify it. *)