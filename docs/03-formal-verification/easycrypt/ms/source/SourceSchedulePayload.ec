require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.
require import SourceBitnessDistributions.
require import SourceProgrammedObligations.
require import SourcePublicFieldObligations.
require import SourceScheduleSeed.

(* Payload-level `dmap` schedule: proved via `dmap_comp`
   (`ms3a_bitness_*_source_as_seed_dmap` in `SourceBitnessDistributions.ec`).
   Extensionally equal to the legacy composed form by
   `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap` in
   `SourceBitnessDistributions.ec`. *)

lemma A_ms3a_payload_dmap_bitness_layer_schedule (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.
proof.
rewrite (_ : dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload
           = d_ms3a_bitness_real_source x).
  by rewrite /d_ms3a_bitness_real_source.
rewrite (_ : dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload
           = d_ms3a_bitness_sim_source x s).
  by rewrite /d_ms3a_bitness_sim_source.
rewrite (ms3a_bitness_real_source_as_seed_dmap x)
  (ms3a_bitness_sim_source_as_seed_dmap x s).
rewrite (L_ms3a_bitness_layer_seed_push_real_eq_layer_dmap x)
  (L_ms3a_bitness_layer_seed_push_sim_eq_layer_dmap x s).
exact (A_ms3a_bitness_layer_seed_schedule x s).
qed.

lemma ms3a_ax_real_wf_from_payload_support (x : ms_public_input) :
  (forall (p : ms3a_real_source_payload),
      p \in d_ms3a_real_source_payload x => ms3a_real_payload_programmed_layer p) =>
  ms3a_ax_real_wf x.
proof.
move=> Hsup; rewrite /ms3a_ax_real_wf => real_src Hmem.
rewrite /d_ms3a_bitness_real_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
have Hpl := Hsup p Hp.
move: Hpl; rewrite /ms3a_real_payload_programmed_layer=> Hwfp.
by rewrite Heq.
qed.

lemma ms3a_ax_sim_wf_from_payload_support (x : ms_public_input) (s : seed) :
  (forall (p : ms3a_sim_source_payload),
      p \in d_ms3a_sim_source_payload x s => ms3a_sim_payload_programmed_layer p) =>
  ms3a_ax_sim_wf x s.
proof.
move=> Hsup; rewrite /ms3a_ax_sim_wf => sim_src Hmem.
rewrite /d_ms3a_bitness_sim_source in Hmem.
case/supp_dmap: Hmem=> [p [Hp Heq]].
have Hpl := Hsup p Hp.
move: Hpl; rewrite /ms3a_sim_payload_programmed_layer=> Hwfp.
by rewrite Heq.
qed.

lemma ms3a_ax_public_fields_from_payload_pair_support
  (x : ms_public_input) (s : seed) :
  (forall (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload),
      pr \in d_ms3a_real_source_payload x =>
      ps \in d_ms3a_sim_source_payload x s =>
      ms3a_payload_pair_public_fields_match pr ps) =>
  ms3a_ax_public_fields x s.
proof.
move=> Hpair; rewrite /ms3a_ax_public_fields => real_src sim_src Hr Hs.
rewrite /d_ms3a_bitness_real_source in Hr; case/supp_dmap: Hr=> [pr [Hpr Heqr]].
rewrite /d_ms3a_bitness_sim_source in Hs; case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hm := Hpair pr ps Hpr Hps.
rewrite Heqr Heqs; exact (ms3a_real_sim_public_fields_of_payload_pair pr ps Hm).
qed.

lemma ms3a_ax_prog_layer_from_real_sim_wf (x : ms_public_input) (s : seed) :
  ms3a_ax_real_wf x =>
  ms3a_ax_sim_wf x s =>
  ms3a_ax_prog_layer x s.
proof.
move=> Hrwf Hswf; rewrite /ms3a_ax_prog_layer /ms3a_sources_have_programmed_bitness_layer
  /ms3a_ax_real_wf /ms3a_ax_sim_wf => real_src sim_src Hr Hs.
split.
- exact (Hrwf real_src Hr).
- exact (Hswf sim_src Hs).
qed.

lemma ms3a_ax_bitness_exact_from_payload_support
  (x : ms_public_input) (s : seed) :
  (forall (p : ms3a_real_source_payload),
      p \in d_ms3a_real_source_payload x => ms3a_real_payload_programmed_layer p) =>
  ms3a_ax_bitness_exact x s.
proof.
move=> Hsup; rewrite /ms3a_ax_bitness_exact => real_src sim_src Hr _ i Hi.
rewrite /d_ms3a_bitness_real_source in Hr; case/supp_dmap: Hr=> [pr [Hpr Heqr]].
have Hpl := Hsup pr Hpr.
move: Hpl; rewrite /ms3a_real_payload_programmed_layer=> Hwff.
rewrite -Heqr in Hwff.
exact (MS_3a_bitness_layer_exact_simulation
  real_src.`ms3s_stmt real_src.`ms3s_bits real_src.`ms3s_bitness_global_challenges
  Hwff i Hi).
qed.

lemma ms3a_payload_schedule_equivalence
  (x : ms_public_input) (s : seed) :
  ms3a_ax_real_wf x =>
  ms3a_ax_sim_wf x s =>
  ms3a_ax_public_fields x s =>
  ms3a_ax_prog_layer x s =>
  ms3a_ax_bitness_exact x s =>
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.
proof. by move=> _ _ _ _ _; exact (A_ms3a_payload_dmap_bitness_layer_schedule x s). qed.
