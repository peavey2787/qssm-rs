require import AllCore List Distr.
require import QssmTypes FS SchnorrBranch BitnessOne BitnessVector.
require import SourceTypes SourceConstructors SourceDistributions.
require import SourceProgrammedObligations.

(* Paired public-field seed axioms, `from_seed` lemmas, and payload-support programming. *)

(* Phase-1 spine linkage: if joint support seeds equal the Phase-1 constructors, the four
   field equalities in `A_ms3a_seed_pair_*_source_shared` follow without those axioms. The
   unconditional axioms remain until `d_ms3a_*_payload_seed` is refined to enforce this.

   **Structured joint (`SourceCouplingTypes` / `SourcePayloadDistributions`):** pairs drawn
   from `d_ms3a_real_sim_payload_seed_coupling` agree on all six fields by construction
   once they come from the same spine draw. The axioms below instead range over **independent**
   marginal supports `d_ms3a_{real,sim}_payload_seed`; deriving them from the spine joint
   needs explicit marginal bridges
   `dmap (d_ms3a_seed_spine_joint x s) ms3a_real_payload_seed_of_bitness_layer = d_ms3a_real_payload_seed x`
   (and sim), which are intentionally **not** added as blanket axioms in this phase. *)

lemma L_ms3a_seed_pair_stmt_when_seeds_are_phase1
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  sr = ms3a_phase1_real_payload_from_public_input x =>
  ss = ms3a_phase1_sim_payload_from_public_input x =>
  sr.`ms3rp_stmt = ss.`ms3sp_stmt.
proof.
move=> _ _ -> ->.
by rewrite /ms3a_phase1_real_payload_from_public_input /ms3a_phase1_sim_payload_from_public_input.
qed.

lemma L_ms3a_seed_pair_res_when_seeds_are_phase1
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  sr = ms3a_phase1_real_payload_from_public_input x =>
  ss = ms3a_phase1_sim_payload_from_public_input x =>
  sr.`ms3rp_res = ss.`ms3sp_res.
proof.
move=> _ _ -> ->.
by rewrite /ms3a_phase1_real_payload_from_public_input /ms3a_phase1_sim_payload_from_public_input.
qed.

lemma L_ms3a_seed_pair_comparison_global_when_seeds_are_phase1
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  sr = ms3a_phase1_real_payload_from_public_input x =>
  ss = ms3a_phase1_sim_payload_from_public_input x =>
  sr.`ms3rp_comparison_global_challenge = ss.`ms3sp_comparison_global_challenge.
proof.
move=> _ _ -> ->.
by rewrite /ms3a_phase1_real_payload_from_public_input /ms3a_phase1_sim_payload_from_public_input.
qed.

lemma L_ms3a_seed_pair_bitness_globals_when_seeds_are_phase1
  (x : ms_public_input) (s : seed) (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed) :
  sr \in d_ms3a_real_payload_seed x =>
  ss \in d_ms3a_sim_payload_seed x s =>
  sr = ms3a_phase1_real_payload_from_public_input x =>
  ss = ms3a_phase1_sim_payload_from_public_input x =>
  sr.`ms3rp_bitness_global_challenges = ss.`ms3sp_bitness_global_challenges.
proof.
move=> _ _ -> ->.
by rewrite /ms3a_phase1_real_payload_from_public_input /ms3a_phase1_sim_payload_from_public_input.
qed.

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

axiom A_ms3a_seed_pair_bitness_globals_source_shared
  (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    sr.`ms3rp_bitness_global_challenges = ss.`ms3sp_bitness_global_challenges.

lemma A_ms3a_seed_pair_bitness_globals_on_support (x : ms_public_input) (s : seed) :
  forall (sr : ms3a_real_payload_seed) (ss : ms3a_sim_payload_seed),
    sr \in d_ms3a_real_payload_seed x =>
    ss \in d_ms3a_sim_payload_seed x s =>
    (ms3a_real_payload_from_seed x sr).`ms3rp_bitness_global_challenges =
      (ms3a_sim_payload_from_seed x s ss).`ms3sp_bitness_global_challenges.
proof.
move=> sr ss Hsr Hss.
exact (ms3a_payload_pair_bitness_global_challenges_eq_from_seed_of_seed_eq x s sr ss
  (A_ms3a_seed_pair_bitness_globals_source_shared x s sr ss Hsr Hss)).
qed.

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
