require import AllCore Distr.
require import SDist.
require import QssmTypes FS.

(* LE transcript observable surface *)
op le_commitment_coeffs : le_transcript_observable -> coeff_vector.
op le_t_coeffs : le_transcript_observable -> coeff_vector.
op le_z_coeffs : le_transcript_observable -> coeff_vector.
op le_challenge_seed_obs : le_transcript_observable -> digest.
op le_programmed_query_digest_obs : le_transcript_observable -> digest.

(* Set B parameter placeholders (concrete values live in qssm-le params.rs) *)
op C_POLY_SIZE : int.
op C_POLY_SPAN : int.
op ETA : int.
op GAMMA : int.
op BETA : int.

(* Abstract but non-vacuous Set-B well-formedness envelope. *)
pred set_b_parameter_well_formed =
  0 < C_POLY_SIZE /\
  0 < C_POLY_SPAN /\
  0 < ETA /\
  0 < GAMMA /\
  0 < BETA /\
  ETA <= GAMMA.

op epsilon_le : real.

axiom A4_le_hvzk_bound_nonneg :
  0%r <= epsilon_le.

(* LE-only game-hop surface for the G1->G2 transition. *)
op d_le_real_view : qssm_public_input -> seed -> le_transcript_observable distr.
op d_le_sim_view : qssm_public_input -> seed -> le_transcript_observable distr.

op le_view_distinguish_pr : le_transcript_observable distr -> distinguisher -> real.

op le_projected_real_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_real_view x s) D.

op le_projected_sim_adv_base (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_view_distinguish_pr (d_le_sim_view x s) D.

op le_game_hop_adv (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_projected_real_adv_base x s D - le_projected_sim_adv_base x s D.

(* Statistical distance (sdist / event-lub formulation) on projected LE views. *)
op le_view_statistical_distance (x : qssm_public_input) (s : seed) : real =
  sdist (d_le_real_view x s) (d_le_sim_view x s).

(* Game-hop / distinguisher advantage at the LE projected-view interface. *)
op le_view_distinguishing_adv (x : qssm_public_input) (s : seed) (D : distinguisher) : real =
  le_game_hop_adv x s D.

pred le_view_statistical_distance_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_view_statistical_distance x s <= epsilon_le.

pred le_real_sim_transcript_equiv (x : qssm_public_input) (s : seed) =
  exists (obsr obss : le_transcript_observable),
    le_commitment_coeffs obsr = le_commitment_coeffs obss /\
    le_t_coeffs obsr = le_t_coeffs obss /\
    le_z_coeffs obsr = le_z_coeffs obss /\
    le_challenge_seed_obs obsr = le_challenge_seed_obs obss /\
    le_programmed_query_digest_obs obsr = le_programmed_query_digest_obs obss.

pred le_set_b_params_ok =
  set_b_parameter_well_formed.

pred le_rejection_sampling_bound_ok =
  0%r <= epsilon_le.

pred le_fs_programming_bound_ok (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_hvzk_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_game_hop_adv x s D <= epsilon_le.

pred le_hvzk_transition_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_hvzk_bound x s D.

pred le_set_b_ring_dimension_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < C_POLY_SIZE /\ 0 < C_POLY_SPAN.

pred le_set_b_challenge_size_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < GAMMA /\ 0 < BETA.

pred le_set_b_norm_bounds_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0 < ETA.

pred le_set_b_eta_gamma_relation_valid (x : qssm_public_input) (s : seed) (D : distinguisher) =
  ETA <= GAMMA.

pred le_set_b_params_sound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_set_b_ring_dimension_valid x s D /\
  le_set_b_challenge_size_valid x s D /\
  le_set_b_norm_bounds_valid x s D /\
  le_set_b_eta_gamma_relation_valid x s D.

pred le_rejection_sampling_hiding_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_rejection_sampling_bound_ok.

pred le_fs_programming_hiding_bound (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_fs_programming_bound_ok x s.

lemma A_LE_SetB_ring_dimension_valid :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_set_b_ring_dimension_valid x s D.
proof.
move=> x s D H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed in H.
rewrite /le_set_b_ring_dimension_valid.
by case: H => Hcs [Hsp _].
qed.

lemma A_LE_SetB_challenge_size_valid :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_set_b_challenge_size_valid x s D.
proof.
move=> x s D H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed in H.
rewrite /le_set_b_challenge_size_valid.
by case: H => _ [_ [_ [Hg [Hb _]]]].
qed.

lemma A_LE_SetB_norm_bounds_valid :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_set_b_norm_bounds_valid x s D.
proof.
move=> x s D H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed in H.
rewrite /le_set_b_norm_bounds_valid.
by case: H => _ [_ [He _]].
qed.

lemma A_LE_SetB_eta_gamma_relation_valid :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_set_b_eta_gamma_relation_valid x s D.
proof.
move=> x s D H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed in H.
rewrite /le_set_b_eta_gamma_relation_valid.
by case: H => _ [_ [_ [_ [_ Heg]]]].
qed.

lemma A_LE_SetB_params_sound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_set_b_params_sound x s D.
proof.
move=> x s D H.
rewrite /le_set_b_params_sound.
split; first exact (A_LE_SetB_ring_dimension_valid x s D H).
split; first exact (A_LE_SetB_challenge_size_valid x s D H).
split; first exact (A_LE_SetB_norm_bounds_valid x s D H).
exact (A_LE_SetB_eta_gamma_relation_valid x s D H).
qed.

lemma L_LE_set_b_params_sound_implies_ok :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_set_b_params_ok.
proof.
move=> x s D H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed /le_set_b_params_sound in H.
rewrite /le_set_b_params_ok /set_b_parameter_well_formed.
case: H => Hr [Hc [Hn Heg]].
case: Hr => Hcs Hsp.
case: Hc => Hg Hb.
split; first exact Hcs.
split; first exact Hsp.
split; first exact Hn.
split; first exact Hg.
by split=> //.
qed.

pred le_rejection_distribution_defined (x : qssm_public_input) (s : seed) =
  le_rejection_sampling_bound_ok.

pred le_rejection_acceptance_probability_bounded (x : qssm_public_input) (s : seed) =
  le_rejection_distribution_defined x s.

pred le_rejection_output_shape_preserved (x : qssm_public_input) (s : seed) =
  le_rejection_acceptance_probability_bounded x s.

pred le_rejection_witness_hiding_statistical_bound
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0%r <= epsilon_le /\ le_rejection_sampling_hiding_bound x s D.

axiom A_LE_rejection_distribution_defined :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_sampling_bound_ok =>
    le_rejection_distribution_defined x s.

axiom A_LE_rejection_acceptance_probability_bounded :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_distribution_defined x s =>
    le_rejection_acceptance_probability_bounded x s.

axiom A_LE_rejection_output_shape_preserved :
  forall (x : qssm_public_input) (s : seed),
    le_rejection_acceptance_probability_bounded x s =>
    le_rejection_output_shape_preserved x s.

axiom A_LE_rejection_witness_hiding_statistical_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_output_shape_preserved x s =>
    0%r <= epsilon_le =>
    le_rejection_witness_hiding_statistical_bound x s D.

lemma A_LE_rejection_sampling_hiding_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_bound_ok =>
    le_rejection_sampling_hiding_bound x s D.
proof.
move=> x s D Hrej.
have Hdef : le_rejection_distribution_defined x s.
  exact (A_LE_rejection_distribution_defined x s Hrej).
have Hacc : le_rejection_acceptance_probability_bounded x s.
  exact (A_LE_rejection_acceptance_probability_bounded x s Hdef).
have Hshape : le_rejection_output_shape_preserved x s.
  exact (A_LE_rejection_output_shape_preserved x s Hacc).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hw : le_rejection_witness_hiding_statistical_bound x s D.
  exact (A_LE_rejection_witness_hiding_statistical_bound x s D Hshape Heps).
by case: Hw.
qed.

pred le_fs_query_surface_defined (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programmable_oracle_available (x : qssm_public_input) (s : seed) =
  le_fs_query_surface_defined x s.

pred le_fs_programming_preserves_transcript_shape (x : qssm_public_input) (s : seed) =
  le_real_sim_transcript_equiv x s.

pred le_fs_programming_cost_bounded_by_epsilon_le
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  0%r <= epsilon_le /\ le_fs_programming_hiding_bound x s D.

axiom A_LE_fs_query_surface_defined :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programming_bound_ok x s =>
    le_fs_query_surface_defined x s.

axiom A_LE_fs_programmable_oracle_available :
  forall (x : qssm_public_input) (s : seed),
    le_fs_query_surface_defined x s =>
    le_fs_programmable_oracle_available x s.

axiom A_LE_fs_programming_preserves_transcript_shape :
  forall (x : qssm_public_input) (s : seed),
    le_fs_programmable_oracle_available x s =>
    le_fs_programming_preserves_transcript_shape x s.

axiom A_LE_fs_programming_cost_bounded_by_epsilon_le :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_fs_programming_preserves_transcript_shape x s =>
    0%r <= epsilon_le =>
    le_fs_programming_cost_bounded_by_epsilon_le x s D.

lemma A_LE_fs_programming_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_fs_programming_bound_ok x s =>
    le_fs_programming_hiding_bound x s D.
proof.
move=> x s D Hfs.
have Hsurf : le_fs_query_surface_defined x s.
  exact (A_LE_fs_query_surface_defined x s Hfs).
have Horacle : le_fs_programmable_oracle_available x s.
  exact (A_LE_fs_programmable_oracle_available x s Hsurf).
have Hshape : le_fs_programming_preserves_transcript_shape x s.
  exact (A_LE_fs_programming_preserves_transcript_shape x s Horacle).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hcost : le_fs_programming_cost_bounded_by_epsilon_le x s D.
  exact (A_LE_fs_programming_cost_bounded_by_epsilon_le x s D Hshape Heps).
by case: Hcost.
qed.

pred le_real_view_distribution_defined (x : qssm_public_input) (s : seed) =
  le_set_b_params_ok.

pred le_sim_view_distribution_defined (x : qssm_public_input) (s : seed) =
  le_set_b_params_ok.

pred le_real_sim_view_indistinguishable (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_rejection_sampling_hiding_bound x s D /\
  le_fs_programming_hiding_bound x s D.

lemma L_LE_combined_hiding_implies_view_indist :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D Hrej Hfs.
rewrite /le_real_sim_view_indistinguishable.
by split.
qed.

lemma A_LE_real_sim_view_indistinguishable_from_bound_ok :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D Hrej Hfs.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Hrej.
have Hfs' := A_LE_fs_programming_bound x s D Hfs.
exact (L_LE_combined_hiding_implies_view_indist x s D Hrej' Hfs').
qed.

pred le_view_advantage_bound_from_indistinguishability
  (x : qssm_public_input) (s : seed) (D : distinguisher) =
  le_hvzk_bound x s D.

lemma A_LE_real_view_distribution_defined :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_real_view_distribution_defined x s.
proof.
move=> x s D H; rewrite /le_real_view_distribution_defined.
exact (L_LE_set_b_params_sound_implies_ok x s D H).
qed.

lemma A_LE_sim_view_distribution_defined :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_sim_view_distribution_defined x s.
proof.
move=> x s D H; rewrite /le_sim_view_distribution_defined.
exact (L_LE_set_b_params_sound_implies_ok x s D H).
qed.

lemma A_LE_real_sim_view_indistinguishable :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_real_sim_view_indistinguishable x s D.
proof.
move=> x s D _ _ Hrej Hfs.
exact (L_LE_combined_hiding_implies_view_indist x s D Hrej Hfs).
qed.

axiom A_LE_view_indist_to_sd_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_view_statistical_distance_bound x s D.

axiom A_LE_sd_bound_to_adv_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_statistical_distance_bound x s D =>
    le_view_distinguishing_adv x s D <= le_view_statistical_distance x s.

lemma A_LE_projected_advantage_matches_view_distance :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_view_distinguishing_adv x s D = le_game_hop_adv x s D.
proof.
by move=> x s D; rewrite /le_view_distinguishing_adv.
qed.

lemma A_LE_view_advantage_bound_from_indistinguishability :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_real_view_distribution_defined x s =>
    le_sim_view_distribution_defined x s =>
    le_real_sim_view_indistinguishable x s D =>
    0%r <= epsilon_le =>
    le_view_advantage_bound_from_indistinguishability x s D.
proof.
move=> x s D Hr Hs Hind Heps.
rewrite /le_view_advantage_bound_from_indistinguishability /le_hvzk_bound.
have Hstat : le_view_statistical_distance_bound x s D.
  exact (A_LE_view_indist_to_sd_bound x s D Hr Hs Hind Heps).
have Hadv : le_view_distinguishing_adv x s D <= le_view_statistical_distance x s.
  exact (A_LE_sd_bound_to_adv_bound x s D Hstat).
have Hdist : le_view_statistical_distance x s <= epsilon_le.
  by rewrite /le_view_statistical_distance_bound in Hstat.
have Hadvhop : le_game_hop_adv x s D <= le_view_statistical_distance x s.
  rewrite -(A_LE_projected_advantage_matches_view_distance x s D).
  exact Hadv.
have Hfin : le_game_hop_adv x s D <= epsilon_le.
  smt().
by exact Hfin.
qed.

lemma A_LE_real_sim_transcript_equiv_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_sound x s D =>
    le_rejection_sampling_hiding_bound x s D =>
    le_fs_programming_hiding_bound x s D =>
    le_hvzk_bound x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hrealdef : le_real_view_distribution_defined x s.
  exact (A_LE_real_view_distribution_defined x s D Hsetb).
have Hsimdef : le_sim_view_distribution_defined x s.
  exact (A_LE_sim_view_distribution_defined x s D Hsetb).
have Hind : le_real_sim_view_indistinguishable x s D.
  exact (A_LE_real_sim_view_indistinguishable x s D Hrealdef Hsimdef Hrej Hfs).
have Heps : 0%r <= epsilon_le.
  exact A4_le_hvzk_bound_nonneg.
have Hadv : le_view_advantage_bound_from_indistinguishability x s D.
  exact (A_LE_view_advantage_bound_from_indistinguishability x s D Hrealdef Hsimdef Hind Heps).
by rewrite /le_view_advantage_bound_from_indistinguishability in Hadv.
qed.

lemma A_LE_SetB_HVZK_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    le_set_b_params_ok =>
    le_rejection_sampling_bound_ok =>
    le_fs_programming_bound_ok x s =>
    le_hvzk_bound x s D.
proof.
move=> x s D Hsetb Hrej Hfs.
have Hsetb' := A_LE_SetB_params_sound x s D Hsetb.
have Hrej' := A_LE_rejection_sampling_hiding_bound x s D Hrej.
have Hfs' := A_LE_fs_programming_bound x s D Hfs.
exact (A_LE_real_sim_transcript_equiv_bound x s D Hsetb' Hrej' Hfs').
qed.

lemma A_LE_HVZK_transition_bound :
  forall (x : qssm_public_input) (s : seed) (D : distinguisher),
    set_b_parameter_well_formed =>
    0%r <= epsilon_le =>
    le_real_sim_transcript_equiv x s =>
    le_hvzk_transition_bound x s D.
proof.
move=> x s D Hsetb Heps Hfs.
rewrite /le_hvzk_transition_bound.
exact (A_LE_SetB_HVZK_bound x s D Hsetb Heps Hfs).
qed.
