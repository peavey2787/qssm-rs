require import QssmTypes.
require import AllCore Distr.
require import SDist.
require import LESurface.
require import LERealExecution.

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

   lemma A_LE_rejection_sampler_sdist_bound :
     forall (x : qssm_public_input) (s : seed),
       le_real_view_distribution_defined x s =>
       le_rejection_distribution_defined x s =>
       le_rejection_acceptance_probability_bounded x s =>
       le_rejection_output_shape_preserved x s =>
       sdist (d_le_real_view x s) (d_le_post_rejection_view x s)
         <= (1%r / 2%r) * epsilon_le.

   The two bridge lemmas keep the theorem-facing statement on the current
   facade, while the lower sampler surface here carries the concrete execution
   law and transform that must eventually justify it. *)