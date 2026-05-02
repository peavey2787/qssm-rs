require import AllCore List Distr.
require import QssmTypes.
require import SourceTypes.
require import SourcePayloadDistributions.
require export SourceCouplingTypes.
require import SourceConstructors.

(* Marginal equalities for the product seed coupling (MS-3c parallel:
   `ComparisonCouplingMarginals.ec`, lemmas `L_dmap_dprod_fst_lossless` /
   `L_dmap_dprod_snd_lossless`). *)

lemma L_dmap_dprod_fst_lossless_src ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless db =>
  dmap (da `*` db) fst = da.
proof.
move=> Hll.
rewrite (dprod_marginalL da db (fun (a : 'a) => a)).
rewrite dmap_id.
have Hw: weight db = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma L_dmap_dprod_snd_lossless_src ['a 'b] (da : 'a distr) (db : 'b distr) :
  is_lossless da =>
  dmap (da `*` db) snd = db.
proof.
move=> Hll.
rewrite (dprod_marginalR da db (fun (b : 'b) => b)).
rewrite dmap_id.
have Hw: weight da = 1%r by apply (is_losslessP _ Hll).
rewrite Hw dscalar1.
by [].
qed.

lemma L_ms3a_coupling_seed_real_projection_eq (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3a_sim_payload_seed x s) =>
  d_ms3a_coupling_seed_real_projection x s = d_ms3a_real_payload_seed x.
proof.
move=> Hll.
rewrite /d_ms3a_coupling_seed_real_projection /d_ms3a_real_sim_payload_seed_coupling.
exact (L_dmap_dprod_fst_lossless_src (d_ms3a_real_payload_seed x) (d_ms3a_sim_payload_seed x s) Hll).
qed.

lemma L_ms3a_coupling_seed_sim_projection_eq (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3a_real_payload_seed x) =>
  d_ms3a_coupling_seed_sim_projection x s = d_ms3a_sim_payload_seed x s.
proof.
move=> Hll.
rewrite /d_ms3a_coupling_seed_sim_projection /d_ms3a_real_sim_payload_seed_coupling.
exact (L_dmap_dprod_snd_lossless_src (d_ms3a_real_payload_seed x) (d_ms3a_sim_payload_seed x s) Hll).
qed.

lemma L_ms3a_coupling_seed_mem_components (x : ms_public_input) (s : seed)
  (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  (sr, ss) \in d_ms3a_real_sim_payload_seed_coupling x s =>
  sr \in d_ms3a_real_payload_seed x /\
  ss \in d_ms3a_sim_payload_seed x s.
proof.
move=> Hmem.
rewrite /d_ms3a_real_sim_payload_seed_coupling in Hmem.
rewrite supp_dprod in Hmem.
by case: Hmem.
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
