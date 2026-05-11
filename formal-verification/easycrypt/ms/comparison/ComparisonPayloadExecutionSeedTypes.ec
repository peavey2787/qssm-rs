require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.

(* MS-3c comparison-local execution-seed package: lift the retained
  payload-seed surface into execution carriers with derived ROM/transcript
  projections, support invariants, and losslessness. *)

type ms3c_execution_seed_package = {
  ms3cep_challenge : ms3c_seed_challenge;
  ms3cep_announcement : ms3c_seed_announcement;
  ms3cep_rom_row : (digest * scalar);
  ms3cep_transcript_openings : ms_comparison_openings;
}.

type ms3c_real_execution_seed = ms3c_execution_seed_package.
type ms3c_sim_execution_seed = ms3c_execution_seed_package.

op ms3c_execution_seed_package_of_seed_components
  (sc : ms3c_seed_challenge) (sa : ms3c_seed_announcement) :
  ms3c_execution_seed_package =
  {| ms3cep_challenge = sc;
     ms3cep_announcement = sa;
     ms3cep_rom_row = ms3c_seed_challenge_coin_driven_rom_row sc;
     ms3cep_transcript_openings =
       ms3c_seed_announcement_coin_driven_transcript_openings sa |}.

op ms3c_payload_seed_of_execution_seed_package
  (sigma : ms3c_execution_seed_package) :
  (ms3c_seed_challenge * ms3c_seed_announcement) =
  (sigma.`ms3cep_challenge, sigma.`ms3cep_announcement).

op ms3c_real_execution_seed_of_payload_seed
  (sr : ms3c_real_payload_seed) : ms3c_real_execution_seed =
  ms3c_execution_seed_package_of_seed_components sr.`1 sr.`2.

op ms3c_sim_execution_seed_of_payload_seed
  (ss : ms3c_sim_payload_seed) : ms3c_sim_execution_seed =
  ms3c_execution_seed_package_of_seed_components ss.`1 ss.`2.

op ms3c_real_payload_seed_of_execution_seed
  (sigma : ms3c_real_execution_seed) : ms3c_real_payload_seed =
  ms3c_payload_seed_of_execution_seed_package sigma.

op ms3c_sim_payload_seed_of_execution_seed
  (sigma : ms3c_sim_execution_seed) : ms3c_sim_payload_seed =
  ms3c_payload_seed_of_execution_seed_package sigma.

op d_ms3c_real_execution_seed (x : ms_public_input) : ms3c_real_execution_seed distr =
  dmap (d_ms3c_real_payload_seed x) ms3c_real_execution_seed_of_payload_seed.

op d_ms3c_sim_execution_seed (x : ms_public_input) (s : seed) : ms3c_sim_execution_seed distr =
  dmap (d_ms3c_sim_payload_seed x s) ms3c_sim_execution_seed_of_payload_seed.

op d_ms3c_real_execution_rom_row (x : ms_public_input) : (digest * scalar) distr =
  dmap (d_ms3c_real_execution_seed x) (fun sigma => sigma.`ms3cep_rom_row).

op d_ms3c_sim_execution_rom_row (x : ms_public_input) (s : seed) : (digest * scalar) distr =
  dmap (d_ms3c_sim_execution_seed x s) (fun sigma => sigma.`ms3cep_rom_row).

op d_ms3c_real_execution_transcript_openings (x : ms_public_input) : ms_comparison_openings distr =
  dmap (d_ms3c_real_execution_seed x) (fun sigma => sigma.`ms3cep_transcript_openings).

op d_ms3c_sim_execution_transcript_openings (x : ms_public_input) (s : seed) : ms_comparison_openings distr =
  dmap (d_ms3c_sim_execution_seed x s) (fun sigma => sigma.`ms3cep_transcript_openings).

lemma L_ms3c_real_payload_seed_of_execution_seed_roundtrip
  (sr : ms3c_real_payload_seed) :
  ms3c_real_payload_seed_of_execution_seed
    (ms3c_real_execution_seed_of_payload_seed sr) = sr.
proof.
case: sr=> sc sa /=.
by rewrite /ms3c_real_payload_seed_of_execution_seed
  /ms3c_real_execution_seed_of_payload_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma L_ms3c_sim_payload_seed_of_execution_seed_roundtrip
  (ss : ms3c_sim_payload_seed) :
  ms3c_sim_payload_seed_of_execution_seed
    (ms3c_sim_execution_seed_of_payload_seed ss) = ss.
proof.
case: ss=> sc sa /=.
by rewrite /ms3c_sim_payload_seed_of_execution_seed
  /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma L_ms3c_real_execution_seed_support_inv
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  exists (sr : ms3c_real_payload_seed),
    sr \in d_ms3c_real_payload_seed x /\
    sigma = ms3c_real_execution_seed_of_payload_seed sr.
proof.
move=> Hsigma.
rewrite /d_ms3c_real_execution_seed in Hsigma.
case/supp_dmap: Hsigma=> sr [Hsr ->].
by exists sr.
qed.

lemma L_ms3c_sim_execution_seed_support_inv
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  sigma \in d_ms3c_sim_execution_seed x s =>
  exists (ss : ms3c_sim_payload_seed),
    ss \in d_ms3c_sim_payload_seed x s /\
    sigma = ms3c_sim_execution_seed_of_payload_seed ss.
proof.
move=> Hsigma.
rewrite /d_ms3c_sim_execution_seed in Hsigma.
case/supp_dmap: Hsigma=> ss [Hss ->].
by exists ss.
qed.

lemma L_ms3c_real_execution_seed_aux_views_on_support
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  sigma.`ms3cep_rom_row =
    (ms3c_phase1_seed_query_digest x,
     sigma.`ms3cep_challenge.`ms3csc_rom_coin) /\
  sigma.`ms3cep_transcript_openings =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x,
          sigma.`ms3cep_announcement.`ms3csa_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) =>
               (ann, sigma.`ms3cep_announcement.`ms3csa_transcript_coin))
             (ms3c_public_false_announcements x) |}.
proof.
move=> Hsigma.
have [sr [Hsr ->]] := L_ms3c_real_execution_seed_support_inv x sigma Hsigma.
move: Hsr.
case: sr=> sc sa /= Hsr.
rewrite /d_ms3c_real_payload_seed supp_dprod in Hsr.
move: Hsr=> [Hsc Hsa].
have Hrow :
    ms3c_seed_challenge_coin_driven_rom_row sc =
    (ms3c_phase1_seed_query_digest x, sc.`ms3csc_rom_coin).
  rewrite /d_ms3c_real_seed_challenge in Hsc.
  case/supp_dmap: Hsc=> rom_coin [_ Hsc].
  by rewrite Hsc /ms3c_seed_challenge_coin_driven_rom_row
    /ms3c_seed_challenge_with_rom_coin /=.
have Hopen :
    ms3c_seed_announcement_coin_driven_transcript_openings sa =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x, sa.`ms3csa_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) => (ann, sa.`ms3csa_transcript_coin))
             (ms3c_public_false_announcements x) |}.
  rewrite /d_ms3c_real_seed_announcement in Hsa.
  case/supp_dmap: Hsa=> transcript_coin [_ Hsa].
  by rewrite Hsa /ms3c_seed_announcement_coin_driven_transcript_openings
    /ms3c_seed_announcement_with_transcript_coin /=.
rewrite /ms3c_real_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
by rewrite Hrow Hopen.
qed.

lemma L_ms3c_sim_execution_seed_aux_views_on_support
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  sigma \in d_ms3c_sim_execution_seed x s =>
  sigma.`ms3cep_rom_row =
    (ms3c_phase1_seed_query_digest x,
     sigma.`ms3cep_challenge.`ms3csc_rom_coin) /\
  sigma.`ms3cep_transcript_openings =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x,
          sigma.`ms3cep_announcement.`ms3csa_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) =>
               (ann, sigma.`ms3cep_announcement.`ms3csa_transcript_coin))
             (ms3c_public_false_announcements x) |}.
proof.
move=> Hsigma.
have [ss [Hss ->]] := L_ms3c_sim_execution_seed_support_inv x s sigma Hsigma.
move: Hss.
case: ss=> sc sa /= Hss.
rewrite /d_ms3c_sim_payload_seed supp_dprod in Hss.
move: Hss=> [Hsc Hsa].
have Hrow :
    ms3c_seed_challenge_coin_driven_rom_row sc =
    (ms3c_phase1_seed_query_digest x, sc.`ms3csc_rom_coin).
  rewrite /d_ms3c_sim_seed_challenge in Hsc.
  case/supp_dmap: Hsc=> rom_coin [_ Hsc].
  by rewrite Hsc /ms3c_seed_challenge_coin_driven_rom_row
    /ms3c_seed_challenge_with_rom_coin /=.
have Hopen :
    ms3c_seed_announcement_coin_driven_transcript_openings sa =
    {| mscos_true_opening =
         (ms3c_public_true_announcement x, sa.`ms3csa_transcript_coin);
       mscos_false_openings =
         map (fun (ann : sch_point) => (ann, sa.`ms3csa_transcript_coin))
             (ms3c_public_false_announcements x) |}.
  rewrite /d_ms3c_sim_seed_announcement in Hsa.
  case/supp_dmap: Hsa=> transcript_coin [_ Hsa].
  by rewrite Hsa /ms3c_seed_announcement_coin_driven_transcript_openings
    /ms3c_seed_announcement_with_transcript_coin /=.
rewrite /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
by rewrite Hrow Hopen.
qed.

lemma L_ms3c_real_execution_seed_law_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_execution_seed x).
proof.
rewrite /d_ms3c_real_execution_seed.
apply dmap_ll.
rewrite /d_ms3c_real_payload_seed.
apply dprod_ll_auto.
- by rewrite /d_ms3c_real_seed_challenge; apply dmap_ll; apply duni_scalar_lossless.
by rewrite /d_ms3c_real_seed_announcement; apply dmap_ll; apply duni_scalar_lossless.
qed.

lemma L_ms3c_sim_execution_seed_law_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_execution_seed x s).
proof.
rewrite /d_ms3c_sim_execution_seed.
apply dmap_ll.
rewrite /d_ms3c_sim_payload_seed.
apply dprod_ll_auto.
- by rewrite /d_ms3c_sim_seed_challenge; apply dmap_ll; apply duni_scalar_lossless.
by rewrite /d_ms3c_sim_seed_announcement; apply dmap_ll; apply duni_scalar_lossless.
qed.