require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.
require import SourceProgrammedObligations SourcePublicFieldObligations.

(* Schedule: seed-level coupling axiom + payload form proved via `dmap_comp`
   (`ms3a_bitness_*_source_as_seed_dmap` in `SourceBitnessDistributions.ec`).
   Stated as a single `dmap` per side off abstract seed laws through the layer maps
   (no `from_seed` composition): extensionally equal to the legacy composed form by
   `L_ms3a_bitness_layer_seed_push_{real,sim}_eq_layer_dmap` in
   `SourceBitnessDistributions.ec`. *)

(* Seed schedule: **proved** from narrow spine marginal bridges
   (`A_ms3a_spine_{real,sim}_marginal_matches_seed` in `SourcePayloadDistributions.ec`) by
   folding nested `dmap`s (`dmap_comp`) and `eq_dmap_in` with definitional inversion on the
   spine record (same six-field round-trip as
   `L_ms3a_bitness_layer_of_{real,sim}_payload_seed_of_bitness` in `SourceConstructors.ec`). *)

lemma A_ms3a_bitness_layer_seed_schedule (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_payload_seed x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_payload_seed x s) ms3a_bitness_layer_source_of_sim_payload.
proof.
rewrite -(A_ms3a_spine_real_marginal_matches_seed x s)
  -(A_ms3a_spine_sim_marginal_matches_seed x s).
rewrite (dmap_comp ms3a_real_payload_seed_of_bitness_layer
  ms3a_bitness_layer_source_of_real_payload (d_ms3a_seed_spine_joint x s)).
rewrite (dmap_comp ms3a_sim_payload_seed_of_bitness_layer
  ms3a_bitness_layer_source_of_sim_payload (d_ms3a_seed_spine_joint x s)).
apply eq_dmap_in=> src _ /=.
case: src=> ms3s_stmt ms3s_result ms3s_bits ms3s_bitness_global_challenges
  ms3s_comparison_global_challenge ms3s_transcript_digest.
by rewrite /ms3a_bitness_layer_source_of_real_payload /ms3a_real_payload_seed_of_bitness_layer
  /ms3a_bitness_layer_source_of_sim_payload /ms3a_sim_payload_seed_of_bitness_layer
  /ms3a_make_real_source /ms3a_make_sim_source /=.
qed.

lemma L_ms3a_bitness_layer_seed_schedule_composed_form (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_payload_seed x)
    (ms3a_bitness_layer_source_of_real_payload \o ms3a_real_payload_from_seed x) =
  dmap (d_ms3a_sim_payload_seed x s)
    (ms3a_bitness_layer_source_of_sim_payload \o ms3a_sim_payload_from_seed x s).
proof.
rewrite (L_ms3a_bitness_layer_seed_push_real_eq_layer_dmap x)
  (L_ms3a_bitness_layer_seed_push_sim_eq_layer_dmap x s).
exact (A_ms3a_bitness_layer_seed_schedule x s).
qed.

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

lemma ms3a_source_eq_from_bitness_layer (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.
proof.
rewrite /d_ms3a_bitness_real_source /d_ms3a_bitness_sim_source.
exact (A_ms3a_payload_dmap_bitness_layer_schedule x s).
qed.

lemma ms3a_real_source_constructor_wf
  (x : ms_public_input) :
  forall (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td
      \in d_ms3a_bitness_real_source x =>
    ms3a_source_wf (ms3a_make_real_source stmt rbit bits bitness_glob comp_glob td).
proof.
move=> stmt rbit bits bitness_glob comp_glob td Hin.
rewrite /d_ms3a_bitness_real_source in Hin.
case/supp_dmap: Hin=> [p [Hp Heq]].
have Hpl : ms3a_real_payload_programmed_layer p.
- exact (ms3a_payload_real_support_programmed x p Hp).
rewrite Heq.
rewrite /ms3a_real_payload_programmed_layer.
exact Hpl.
qed.

lemma ms3a_sim_source_constructor_wf
  (x : ms_public_input) (s : seed) :
  forall (stmt : digest) (rbit : bool) (bits : ms_single_bit_or_transcript list)
    (bitness_glob : digest list) (comp_glob td : digest),
    ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_source_wf (ms3a_make_sim_source stmt rbit bits bitness_glob comp_glob td).
proof.
move=> stmt rbit bits bitness_glob comp_glob td Hin.
rewrite /d_ms3a_bitness_sim_source in Hin.
case/supp_dmap: Hin=> [p [Hp Heq]].
have Hpl : ms3a_sim_payload_programmed_layer p.
- exact (ms3a_payload_sim_support_programmed x s p Hp).
rewrite Heq.
rewrite /ms3a_sim_payload_programmed_layer.
exact Hpl.
qed.

lemma ms3a_source_constructors_same_public_fields
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields
      (ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r)
      (ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s).
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin.
rewrite /d_ms3a_bitness_real_source in Hrin.
rewrite /d_ms3a_bitness_sim_source in Hsin.
case/supp_dmap: Hrin=> [pr [Hpr Heqr]].
case/supp_dmap: Hsin=> [ps [Hps Heqs]].
have Hpp : ms3a_payload_pair_public_fields_match pr ps.
- exact (ms3a_payload_pair_public_fields_on_support x s pr ps Hpr Hps).
rewrite Heqr Heqs.
exact (ms3a_real_sim_public_fields_of_payload_pair pr ps Hpp).
qed.

lemma ms3a_source_constructors_programmed_bitness
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer
      (ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r)
      (ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s).
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin.
rewrite /ms3a_sources_have_programmed_bitness_layer.
split.
- exact (ms3a_real_source_constructor_wf x stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r Hrin).
- exact (ms3a_sim_source_constructor_wf x s stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s Hsin).
qed.

lemma ms3a_source_constructors_bitness_exact
  (x : ms_public_input) (s : seed) :
  forall (stmt_r stmt_s : digest) (res_r res_s : bool)
    (bits_r bits_s : ms_single_bit_or_transcript list)
    (bitness_glob_r bitness_glob_s : digest list)
    (comp_glob_r comp_glob_s td_r td_s : digest),
    ms3a_make_real_source stmt_r res_r bits_r bitness_glob_r comp_glob_r td_r
      \in d_ms3a_bitness_real_source x =>
    ms3a_make_sim_source stmt_s res_s bits_s bitness_glob_s comp_glob_s td_s
      \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed stmt_r i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> stmt_r stmt_s res_r res_s bits_r bits_s bitness_glob_r bitness_glob_s
  comp_glob_r comp_glob_s td_r td_s Hrin Hsin i Hi.
rewrite /d_ms3a_bitness_real_source in Hrin.
case/supp_dmap: Hrin=> [pr [Hpr Heqr]].
have Hpl : ms3a_real_payload_programmed_layer pr.
- exact (ms3a_payload_real_support_programmed x pr Hpr).
move: Hpl; rewrite /ms3a_real_payload_programmed_layer /ms3a_source_wf=> Hprog.
rewrite -Heqr /ms3a_make_real_source in Hprog.
exact (MS_3a_bitness_layer_exact_simulation stmt_r bits_r bitness_glob_r Hprog i Hi).
qed.
