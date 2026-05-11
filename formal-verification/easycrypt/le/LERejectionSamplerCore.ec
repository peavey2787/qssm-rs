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

(* Core rejection-sampler shadow state and constructor lane below the facade. *)

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