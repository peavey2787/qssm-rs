require import QssmTypes.
require import LESurface.

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
