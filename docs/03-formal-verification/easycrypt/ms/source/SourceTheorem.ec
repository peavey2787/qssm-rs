require import AllCore List Distr.
require import QssmTypes FS BitnessOne BitnessVector Comparison ComparisonTypes ComparisonDigests ComparisonPayloads ComparisonCoupling ComparisonTheorem TranscriptObservable.
require import SourceModel.
require import SourceTypes SourceConstructors SourceDistributions SourceObligations.

(* Packaging bridge: source-level equality implies abstract observable equality.
   Layer hypotheses (Schnorr/OR-split/A2/vector/observable) are tracked in
   `plans/MS_3a_proof_plan.md`; this lemma is the minimal checker-friendly statement
   used by `MS_3a_exact_bitness_simulation` (proof is `ms3a_source_observable_equiv_from_layer`). *)
lemma MS_3a_exact_bitness_simulation_from_layers
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s =>
  ms3a_bitness_real_sim_equiv x s.
proof.
move=> H_src_eq.
exact (ms3a_source_observable_equiv_from_layer x s H_src_eq).
qed.

(* Recover constructor witnesses via the defining `dmap` preimage (payload). *)
lemma ms3a_source_wf_of_real_mem
  (x : ms_public_input) (real_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x => ms3a_source_wf real_src.
proof.
move=> Hin.
have Hmem : real_src \in d_ms3a_bitness_real_source x by exact Hin.
rewrite /d_ms3a_bitness_real_source in Hin.
case/supp_dmap: Hin=> [p [Hp Hfeq]].
have Hflip : ms3a_bitness_layer_source_of_real_payload p = real_src by rewrite Hfeq.
have Hin' := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload p) real_src Hflip Hmem.
apply (ms3a_source_wf_eq (ms3a_bitness_layer_source_of_real_payload p) real_src
  Hflip).
exact (ms3a_real_source_constructor_wf x p.`ms3rp_stmt p.`ms3rp_res p.`ms3rp_bits
  p.`ms3rp_bitness_global_challenges p.`ms3rp_comparison_global_challenge
  p.`ms3rp_transcript_digest Hin').
qed.

lemma ms3a_source_wf_of_sim_mem
  (x : ms_public_input) (s : seed) (sim_src : ms3a_bitness_layer_source) :
  sim_src \in d_ms3a_bitness_sim_source x s => ms3a_source_wf sim_src.
proof.
move=> Hin.
have Hmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hin.
rewrite /d_ms3a_bitness_sim_source in Hin.
case/supp_dmap: Hin=> [p [Hp Hfeq]].
have Hflip : ms3a_bitness_layer_source_of_sim_payload p = sim_src by rewrite Hfeq.
have Hin' := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload p) sim_src Hflip Hmem.
apply (ms3a_source_wf_eq (ms3a_bitness_layer_source_of_sim_payload p) sim_src
  Hflip).
exact (ms3a_sim_source_constructor_wf x s p.`ms3sp_stmt p.`ms3sp_res p.`ms3sp_bits
  p.`ms3sp_bitness_global_challenges p.`ms3sp_comparison_global_challenge
  p.`ms3sp_transcript_digest Hin').
qed.

lemma ms3a_public_fields_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_real_sim_sources_match_public_fields real_src sim_src.
proof.
move=> Hr Hs.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hm := ms3a_source_constructors_same_public_fields x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin.
exact (ms3a_public_match_respects
  (ms3a_bitness_layer_source_of_real_payload pr) real_src
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflipr Hflips Hm).
qed.

lemma ms3a_prog_layer_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  ms3a_sources_have_programmed_bitness_layer real_src sim_src.
proof.
move=> Hr Hs.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hm := ms3a_source_constructors_programmed_bitness x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin.
exact (ms3a_prog_layer_respects
  (ms3a_bitness_layer_source_of_real_payload pr) real_src
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflipr Hflips Hm).
qed.

lemma ms3a_bitness_exact_of_mem_pair
  (x : ms_public_input) (s : seed)
  (real_src sim_src : ms3a_bitness_layer_source) :
  real_src \in d_ms3a_bitness_real_source x =>
  sim_src \in d_ms3a_bitness_sim_source x s =>
  forall (i : int), ms_bit_index_valid i =>
  exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
    ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
    ms_challenges_split c0 c1 cglob /\
    d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
    d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
proof.
move=> Hr Hs i Hi.
have Hrmem : real_src \in d_ms3a_bitness_real_source x by exact Hr.
have Hsmem : sim_src \in d_ms3a_bitness_sim_source x s by exact Hs.
rewrite /d_ms3a_bitness_real_source in Hr.
rewrite /d_ms3a_bitness_sim_source in Hs.
case/supp_dmap: Hr=> [pr [Hpr Heqr]].
case/supp_dmap: Hs=> [ps [Hps Heqs]].
have Hflipr : ms3a_bitness_layer_source_of_real_payload pr = real_src by rewrite Heqr.
have Hflips : ms3a_bitness_layer_source_of_sim_payload ps = sim_src by rewrite Heqs.
have Hrin := distr_mem_eq (d_ms3a_bitness_real_source x)
  (ms3a_bitness_layer_source_of_real_payload pr) real_src Hflipr Hrmem.
have Hsin := distr_mem_eq (d_ms3a_bitness_sim_source x s)
  (ms3a_bitness_layer_source_of_sim_payload ps) sim_src Hflips Hsmem.
have Hax := ms3a_source_constructors_bitness_exact x s
  pr.`ms3rp_stmt ps.`ms3sp_stmt pr.`ms3rp_res ps.`ms3sp_res
  pr.`ms3rp_bits ps.`ms3sp_bits
  pr.`ms3rp_bitness_global_challenges ps.`ms3sp_bitness_global_challenges
  pr.`ms3rp_comparison_global_challenge ps.`ms3sp_comparison_global_challenge
  pr.`ms3rp_transcript_digest ps.`ms3sp_transcript_digest Hrin Hsin i Hi.
have Hres : exists (w0 w1 c0 c1 cglob : scalar) (d0 d1 : digest),
  ms_bitness_fs_programmed real_src.`ms3s_stmt i d0 d1 cglob /\
  ms_challenges_split c0 c1 cglob /\
  d_ms_bit_or_real_bitfalse w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1 /\
  d_ms_bit_or_real_bittrue w0 w1 c0 c1 = d_ms_bit_or_sim_both w0 w1 c0 c1.
- by rewrite Heqr (ms3a_bitness_real_src_stmt pr); exact Hax.
exact Hres.
qed.

lemma ms3a_default_source_eq
  (x : ms_public_input) (s : seed) :
  d_ms3a_bitness_real_source x = d_ms3a_bitness_sim_source x s.
proof.
have Hrwf : ms3a_ax_real_wf x.
- rewrite /ms3a_ax_real_wf => real_src Hmem.
  exact (ms3a_source_wf_of_real_mem x real_src Hmem).
have Hswf : ms3a_ax_sim_wf x s.
- rewrite /ms3a_ax_sim_wf => sim_src Hmem.
  exact (ms3a_source_wf_of_sim_mem x s sim_src Hmem).
have Hpub : ms3a_ax_public_fields x s.
- rewrite /ms3a_ax_public_fields => real_src sim_src Hr Hs.
  exact (ms3a_public_fields_of_mem_pair x s real_src sim_src Hr Hs).
have Hprog : ms3a_ax_prog_layer x s.
- rewrite /ms3a_ax_prog_layer => real_src sim_src Hr Hs.
  exact (ms3a_prog_layer_of_mem_pair x s real_src sim_src Hr Hs).
have Hex : ms3a_ax_bitness_exact x s.
- rewrite /ms3a_ax_bitness_exact => real_src sim_src Hr Hs i Hi.
  exact (ms3a_bitness_exact_of_mem_pair x s real_src sim_src Hr Hs i Hi).
exact (ms3a_source_eq_from_bitness_layer x s Hrwf Hswf Hpub Hprog Hex).
qed.

op ms3a_default_observable_v2 : ms_v2_transcript_observable =
  ms3a_pack_observable_with_digest
    witness.`msv2_statement_digest witness.`msv2_result_bit
    witness.`msv2_bitness_global_challenges witness.`msv2_comparison_global_challenge
.

lemma ms3a_default_transcript_digest_consistent :
  ms_transcript_digest_of_observable ms3a_default_observable_v2.
proof.
exact (ms3a_pack_observable_with_digest_consistent
  witness.`msv2_statement_digest witness.`msv2_result_bit
  witness.`msv2_bitness_global_challenges
  witness.`msv2_comparison_global_challenge).
qed.

lemma ms3a_default_frame_consistent :
  ms3a_frame_consistent (ms3a_observable_of_v2 ms3a_default_observable_v2)
    ms3a_default_observable_v2.
proof.
exact (MS_3a_frame_consistent_of_v2
  ms3a_default_observable_v2 ms3a_default_transcript_digest_consistent).
qed.

lemma MS_3a_exact_bitness_simulation (x : ms_public_input) (s : seed) :
  ms3a_bitness_real_sim_equiv x s.
proof.
apply (@MS_3a_exact_bitness_simulation_from_layers x s).
exact (ms3a_default_source_eq x s).
qed.
