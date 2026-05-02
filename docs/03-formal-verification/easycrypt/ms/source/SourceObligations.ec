require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.

(* Generic source-packaging obligation (non-crypto): premise-driven source
   distribution equality from well-formedness, public-field alignment, and
   bitness-layer exact-simulation premises. *)
pred ms3a_ax_real_wf (x : ms_public_input) =
  forall (real_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.

pred ms3a_ax_sim_wf (x : ms_public_input) (s : seed) =
  forall (sim_src : ms3a_bitness_layer_source),
    sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.

pred ms3a_ax_public_fields (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_real_sim_sources_match_public_fields real_src sim_src.

pred ms3a_ax_prog_layer (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    ms3a_sources_have_programmed_bitness_layer real_src sim_src.

pred ms3a_ax_bitness_exact (x : ms_public_input) (s : seed) =
  forall (real_src sim_src : ms3a_bitness_layer_source),
    real_src \in d_ms3a_bitness_real_source x =>
    sim_src \in d_ms3a_bitness_sim_source x s =>
    forall (i : int), ms_bit_index_valid i =>
    exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
      ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
      ms_challenges_split c0 c1 cglob /\
      d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
      d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.

(* MS-3a hardening: scheduling debt is axiomatized as a **single** unconditional
   payload-level `dmap` equality (`A_ms3a_payload_dmap_bitness_layer_schedule`).
   Support/public-field facts on **payload** support are **proved lemmas**
   (`ms3a_payload_*_support_programmed`, `ms3a_payload_pair_public_fields_on_support`)
   from **narrower seed-support axioms** (real: `A_ms3a_real_seed_bits_programmed_on_support`,
   `A_ms3a_real_seed_bitness_globals_programmed_on_support` with lemma
   `A_ms3a_real_seed_programmed_on_support`; sim: `A_ms3a_sim_seed_bits_programmed_on_support`,
   `A_ms3a_sim_seed_bitness_globals_programmed_on_support` with lemma
   `A_ms3a_sim_seed_programmed_on_support`; paired public fields: axiom
   `A_ms3a_seed_pair_stmt_source_shared` plus lemma `A_ms3a_seed_pair_stmt_on_support`,
   `A_ms3a_seed_pair_res_source_shared` plus lemma `A_ms3a_seed_pair_res_on_support`,
   `A_ms3a_seed_pair_comparison_global_source_shared` plus lemma
   `A_ms3a_seed_pair_comparison_global_on_support`, and axiom
   `A_ms3a_seed_pair_bitness_globals_on_support`, with
   `A_ms3a_seed_pair_public_fields_on_support` proved as a lemma)
   plus the defining pushforwards `d_ms3a_{real,sim}_source_payload` =
   `dmap (d_ms3a_*_payload_seed) …` in `SourceDistributions.ec`. The five `ms3a_ax_*`
   predicates are **proved lemmas** below from those payload-support lemmas. Legacy
   packaging: `ms3a_payload_schedule_equivalence` (comment above its statement). *)

(* Seed-level obligations (narrower than payload support: quantify over seeds in
   `d_ms3a_{real,sim}_payload_seed` only). Payload support lemmas below follow by
   `supp_dmap` from the defining pushforwards of `d_ms3a_{real,sim}_source_payload`. *)

(* Real seed programmed layer splits along `ms_bitness_vector_programmed_layer`
   (`BitnessVector.ec`): per-bit programmed transcripts + ordered global digest vector. *)
axiom A_ms3a_real_seed_bits_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms_per_bit_programmed sigma.`ms3rp_stmt sigma.`ms3rp_bits.

axiom A_ms3a_real_seed_bitness_globals_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms_ordered_challenge_vector_matches sigma.`ms3rp_bits
      sigma.`ms3rp_bitness_global_challenges.

lemma A_ms3a_real_seed_programmed_on_support (x : ms_public_input) :
  forall (sigma : ms3a_real_payload_seed),
    sigma \in d_ms3a_real_payload_seed x =>
    ms3a_real_payload_programmed_layer (ms3a_real_payload_from_seed x sigma).
proof.
move=> sigma Hsig.
rewrite ms3a_real_payload_from_seed_def /ms3a_real_payload_programmed_layer
  /ms3a_bitness_layer_source_of_real_payload /ms3a_make_real_source /ms3a_source_wf
  /ms_bitness_vector_programmed_layer.
split.
- exact (A_ms3a_real_seed_bits_programmed_on_support x sigma Hsig).
- exact (A_ms3a_real_seed_bitness_globals_programmed_on_support x sigma Hsig).
qed.

(* Sim seed: same `ms_bitness_vector_programmed_layer` split as real (keyed by `s`). *)
axiom A_ms3a_sim_seed_bits_programmed_on_support (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms_per_bit_programmed sigma.`ms3sp_stmt sigma.`ms3sp_bits.

axiom A_ms3a_sim_seed_bitness_globals_programmed_on_support
  (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms_ordered_challenge_vector_matches sigma.`ms3sp_bits
      sigma.`ms3sp_bitness_global_challenges.

lemma A_ms3a_sim_seed_programmed_on_support (x : ms_public_input) (s : seed) :
  forall (sigma : ms3a_sim_payload_seed),
    sigma \in d_ms3a_sim_payload_seed x s =>
    ms3a_sim_payload_programmed_layer (ms3a_sim_payload_from_seed x s sigma).
proof.
move=> sigma Hsig.
rewrite ms3a_sim_payload_from_seed_def /ms3a_sim_payload_programmed_layer
  /ms3a_bitness_layer_source_of_sim_payload /ms3a_make_sim_source /ms3a_source_wf
  /ms_bitness_vector_programmed_layer.
split.
- exact (A_ms3a_sim_seed_bits_programmed_on_support x s sigma Hsig).
- exact (A_ms3a_sim_seed_bitness_globals_programmed_on_support x s sigma Hsig).
qed.

(* Narrow paired-public obligations: joint seed support (stmt, result bit, comparison
   global challenge, bitness globals). Stmt / res / comparison-global: **axioms**
   `A_ms3a_seed_pair_stmt_source_shared`, `A_ms3a_seed_pair_res_source_shared`,
   `A_ms3a_seed_pair_comparison_global_source_shared` on seed record fields; **lemmata**
   `A_ms3a_seed_pair_stmt_on_support`, `A_ms3a_seed_pair_res_on_support`,
   `A_ms3a_seed_pair_comparison_global_on_support` for `from_seed` payloads. *)
axiom A_ms3a_seed_pair_stmt_source_shared (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    sr.`ms3rp_stmt = ss.`ms3sp_stmt.

lemma A_ms3a_seed_pair_stmt_on_support (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    (ms3a_real_payload_from_seed x sr).`ms3rp_stmt =
      (ms3a_sim_payload_from_seed x s ss).`ms3sp_stmt.
proof.
move=> sr ss Hsr Hss.
exact (ms3a_payload_pair_stmt_eq_from_seed_of_seed_stmt_eq x s sr ss
  (A_ms3a_seed_pair_stmt_source_shared x s sr ss Hsr Hss)).
qed.

axiom A_ms3a_seed_pair_res_source_shared (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    sr.`ms3rp_res = ss.`ms3sp_res.

lemma A_ms3a_seed_pair_res_on_support (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    (ms3a_real_payload_from_seed x sr).`ms3rp_res =
      (ms3a_sim_payload_from_seed x s ss).`ms3sp_res.
proof.
move=> sr ss Hsr Hss.
exact (ms3a_payload_pair_res_eq_from_seed_of_seed_res_eq x s sr ss
  (A_ms3a_seed_pair_res_source_shared x s sr ss Hsr Hss)).
qed.

axiom A_ms3a_seed_pair_comparison_global_source_shared
  (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    sr.`ms3rp_comparison_global_challenge = ss.`ms3sp_comparison_global_challenge.

lemma A_ms3a_seed_pair_comparison_global_on_support (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    (ms3a_real_payload_from_seed x sr).`ms3rp_comparison_global_challenge =
      (ms3a_sim_payload_from_seed x s ss).`ms3sp_comparison_global_challenge.
proof.
move=> sr ss Hsr Hss.
exact (ms3a_payload_pair_comparison_global_challenge_eq_from_seed_of_seed_eq x s sr ss
  (A_ms3a_seed_pair_comparison_global_source_shared x s sr ss Hsr Hss)).
qed.

axiom A_ms3a_seed_pair_bitness_globals_on_support (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    sr.`ms3rp_bitness_global_challenges = ss.`ms3sp_bitness_global_challenges.

lemma A_ms3a_seed_pair_public_fields_on_support
  (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    ms3a_payload_pair_public_fields_match
      (ms3a_real_payload_from_seed x sr) (ms3a_sim_payload_from_seed x s ss).
proof.
move=> sr ss Hsr Hss.
rewrite ms3a_real_payload_from_seed_def ms3a_sim_payload_from_seed_def.
rewrite /ms3a_payload_pair_public_fields_match.
split; first exact (A_ms3a_seed_pair_stmt_on_support x s sr ss Hsr Hss).
split; first exact (A_ms3a_seed_pair_res_on_support x s sr ss Hsr Hss).
split; first exact (A_ms3a_seed_pair_comparison_global_on_support x s sr ss Hsr Hss).
exact (A_ms3a_seed_pair_bitness_globals_on_support x s sr ss Hsr Hss).
qed.

lemma ms3a_payload_real_support_programmed (x : ms_public_input) :
  forall (p : ms3a_real_source_payload),
    p \in d_ms3a_real_source_payload x => ms3a_real_payload_programmed_layer p.
proof.
move=> p Hp; move: Hp; rewrite /d_ms3a_real_source_payload => Hp.
case/supp_dmap: Hp=> [sigma [Hsig Heq]].
rewrite Heq; exact (A_ms3a_real_seed_programmed_on_support x sigma Hsig).
qed.

lemma ms3a_payload_sim_support_programmed (x : ms_public_input) (s : seed) :
  forall (p : ms3a_sim_source_payload),
    p \in d_ms3a_sim_source_payload x s => ms3a_sim_payload_programmed_layer p.
proof.
move=> p Hp; move: Hp; rewrite /d_ms3a_sim_source_payload => Hp.
case/supp_dmap: Hp=> [sigma [Hsig Heq]].
rewrite Heq; exact (A_ms3a_sim_seed_programmed_on_support x s sigma Hsig).
qed.

lemma ms3a_payload_pair_public_fields_on_support
  (x : ms_public_input) (s : seed) :
  forall (pr : ms3a_real_source_payload) (ps : ms3a_sim_source_payload),
    pr \in d_ms3a_real_source_payload x =>
    ps \in d_ms3a_sim_source_payload x s =>
    ms3a_payload_pair_public_fields_match pr ps.
proof.
move=> pr ps Hpr Hps; move: Hpr Hps.
rewrite /d_ms3a_real_source_payload /d_ms3a_sim_source_payload => Hpr Hps.
case/supp_dmap: Hpr=> [sr [Hsr Heqr]].
case/supp_dmap: Hps=> [ss [Hss Heqs]].
have Hm := A_ms3a_seed_pair_public_fields_on_support x s sr ss Hsr Hss.
by rewrite Heqr Heqs.
qed.

(* Core residual MS-3a payload coupling obligation: equality of the abstract real
   and sim payload laws after the same bitness-layer constructor (`dmap` through
   `ms3a_bitness_layer_source_of_{real,sim}_payload`). Discharging this is the
   main scheduling/coupling proof once `d_ms3a_{real,sim}_source_payload` are
   instantiated from the execution spec / games. *)
axiom A_ms3a_payload_dmap_bitness_layer_schedule (x : ms_public_input) (s : seed) :
  dmap (d_ms3a_real_source_payload x) ms3a_bitness_layer_source_of_real_payload =
  dmap (d_ms3a_sim_source_payload x s) ms3a_bitness_layer_source_of_sim_payload.

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

(* Compatibility wrapper only (not the core proof obligation): same `dmap`
   conclusion as `A_ms3a_payload_dmap_bitness_layer_schedule`. The five
   `ms3a_ax_*` hypotheses are kept for older call sites / readable scripts but are
   unused in the proof — they are proved separately from the support/public-field
   axioms and do not justify the schedule here. Prefer `A_ms3a_payload_dmap_bitness_layer_schedule`
   or `ms3a_source_eq_from_bitness_layer` for new work. *)
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
