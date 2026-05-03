require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes.
require import SourcePayloadDistributions.
require export SourceCouplingTypes.
require import SourceConstructors.

(* Structured spine joint (`d_ms3a_seed_spine_joint` + pair map): membership preimage,
   projections folded to a single `dmap` off the spine (`Distr.dmap_comp`), and
   `ms3a_ax_seed_coupling_pair_relation` from `ms3a_source_wf` on spine support.

   In `SourcePayloadDistributions.ec`, `d_ms3a_sim_payload_seed` is **defined** as the sim
   marginal of `d_ms3a_seed_spine_joint` (lemma `A_ms3a_spine_sim_marginal_matches_seed` is
   definitional). The joint and **real** seed law remain abstract `op`s; axiom
   `A_ms3a_spine_real_marginal_matches_seed` plus `A_ms3a_seed_spine_support_wf` and
   `A_ms3a_spine_marginal_pair_common_lift` are not proved here without game-level definitions. *)

lemma L_ms3a_real_sim_seed_of_bitness_coupled_of_wf (src : ms3a_bitness_layer_source) :
  ms3a_source_wf src =>
  ms3a_real_sim_payload_seed_coupled
    (ms3a_real_payload_seed_of_bitness_layer src)
    (ms3a_sim_payload_seed_of_bitness_layer src).
proof.
move=> Hwf.
move: Hwf; rewrite /ms3a_source_wf=> Hbit.
have Hpub := L_ms3a_payload_pair_public_fields_seed_of_bitness src.
have Hbits :
  (ms3a_real_payload_seed_of_bitness_layer src).`ms3rp_bits =
  (ms3a_sim_payload_seed_of_bitness_layer src).`ms3sp_bits
  by rewrite /ms3a_real_payload_seed_of_bitness_layer /ms3a_sim_payload_seed_of_bitness_layer.
have Htd :
  (ms3a_real_payload_seed_of_bitness_layer src).`ms3rp_transcript_digest =
  (ms3a_sim_payload_seed_of_bitness_layer src).`ms3sp_transcript_digest
  by rewrite /ms3a_real_payload_seed_of_bitness_layer /ms3a_sim_payload_seed_of_bitness_layer.
rewrite /ms3a_real_sim_payload_seed_coupled.
split; first by exact Hpub.
split; first by exact Hbits.
split; first by exact Htd.
split; first by rewrite /ms3a_real_payload_seed_of_bitness_layer /=; exact Hbit.
by rewrite /ms3a_sim_payload_seed_of_bitness_layer /=; exact Hbit.
qed.

lemma L_ms3a_ax_seed_coupling_pair_relation_of_spine_support_wf
  (x : ms_public_input) (s : seed) :
  (forall (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s => ms3a_source_wf src) =>
  ms3a_ax_seed_coupling_pair_relation x s.
proof.
move=> Hwf sr ss Hmem.
rewrite /d_ms3a_real_sim_payload_seed_coupling in Hmem.
case/supp_dmap: Hmem=> src [Hsrc Heq].
case: Heq => -> ->.
exact (L_ms3a_real_sim_seed_of_bitness_coupled_of_wf src (Hwf src Hsrc)).
qed.

lemma L_ms3a_coupling_seed_mem_spine_preimage
  (x : ms_public_input) (s : seed)
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  (sr, ss) \in d_ms3a_real_sim_payload_seed_coupling x s =>
  exists (src : ms3a_bitness_layer_source),
    src \in d_ms3a_seed_spine_joint x s /\
    sr = ms3a_real_payload_seed_of_bitness_layer src /\
    ss = ms3a_sim_payload_seed_of_bitness_layer src.
proof.
move=> Hmem.
rewrite /d_ms3a_real_sim_payload_seed_coupling in Hmem.
case/supp_dmap: Hmem=> src [Hsrc Heq].
exists src; split; first by [].
by case: Heq.
qed.

lemma L_ms3a_coupling_seed_real_projection_dmap_spine (x : ms_public_input) (s : seed) :
  d_ms3a_coupling_seed_real_projection x s =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer.
proof.
rewrite /d_ms3a_coupling_seed_real_projection /d_ms3a_real_sim_payload_seed_coupling.
by rewrite (dmap_comp ms3a_real_sim_seed_pair_of_bitness_layer fst (d_ms3a_seed_spine_joint x s)).
qed.

lemma L_ms3a_coupling_seed_sim_projection_dmap_spine (x : ms_public_input) (s : seed) :
  d_ms3a_coupling_seed_sim_projection x s =
  dmap (d_ms3a_seed_spine_joint x s) ms3a_sim_payload_seed_of_bitness_layer.
proof.
rewrite /d_ms3a_coupling_seed_sim_projection /d_ms3a_real_sim_payload_seed_coupling.
by rewrite (dmap_comp ms3a_real_sim_seed_pair_of_bitness_layer snd (d_ms3a_seed_spine_joint x s)).
qed.

lemma L_ms3a_real_sim_payload_seed_coupled_layer_maps_eq
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  ms3a_real_sim_payload_seed_coupled sr ss =>
  ms3a_bitness_layer_source_of_real_payload sr =
  ms3a_bitness_layer_source_of_sim_payload ss.
proof.
move=> [Hpub [Hbits [Htd _]]].
have [Hstmt [Hres [Hcomp Hbg]]] := Hpub.
rewrite /ms3a_bitness_layer_source_of_real_payload /ms3a_bitness_layer_source_of_sim_payload
  /ms3a_make_real_source /ms3a_make_sim_source.
by rewrite Hstmt Hres Hbits Hbg Hcomp Htd.
qed.

lemma L_ms3a_real_sim_payload_seed_coupled_implies_public_match
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  ms3a_real_sim_payload_seed_coupled sr ss =>
  ms3a_payload_pair_public_fields_match sr ss.
proof.
by move=> [Hpub _].
qed.
