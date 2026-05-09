require import AllCore Int List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClauseTypes BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes ComparisonPayloadSeedTypes.
require import ComparisonPayloadFromSeed.

(* Execution-seed pushforwards and payload law transport below the stable
  `ComparisonPayloadFromSeed` phase-1/payload surface. *)

op ms3c_real_payload_from_execution_seed
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  ms3c_real_comparison_payload =
  ms3c_real_payload_from_seed x (ms3c_real_payload_seed_of_execution_seed sigma).

op ms3c_sim_payload_from_execution_seed
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  ms3c_sim_comparison_payload =
  ms3c_sim_payload_from_seed x s (ms3c_sim_payload_seed_of_execution_seed sigma).

op d_ms3c_real_execution_comparison_payload
  (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_execution_seed x) (ms3c_real_payload_from_execution_seed x).

op d_ms3c_sim_execution_comparison_payload
  (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_execution_seed x s) (ms3c_sim_payload_from_execution_seed x s).

lemma L_ms3c_real_execution_payload_aux_views_match
  (x : ms_public_input) (sigma : ms3c_real_execution_seed) :
  sigma \in d_ms3c_real_execution_seed x =>
  sigma.`ms3cep_rom_row =
    ms3c_payload_coin_driven_rom_row (ms3c_real_payload_from_execution_seed x sigma) /\
  sigma.`ms3cep_transcript_openings =
    ms3c_payload_coin_driven_transcript_openings
      (ms3c_real_payload_from_execution_seed x sigma).
proof.
move=> Hsigma.
have [sr [Hsr ->]] := L_ms3c_real_execution_seed_support_inv x sigma Hsigma.
clear Hsr.
case: sr=> sc sa /=.
rewrite /ms3c_real_payload_from_execution_seed
  /ms3c_real_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_real_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
split.
- by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_real_payload_from_seed
    /ms3c_payload_from_seed_components /ms3c_seed_challenge_coin_driven_rom_row.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_real_payload_from_seed
  /ms3c_payload_from_seed_components
  /ms3c_seed_announcement_coin_driven_transcript_openings.
qed.

lemma L_ms3c_sim_execution_payload_aux_views_match
  (x : ms_public_input) (s : seed) (sigma : ms3c_sim_execution_seed) :
  sigma \in d_ms3c_sim_execution_seed x s =>
  sigma.`ms3cep_rom_row =
    ms3c_payload_coin_driven_rom_row (ms3c_sim_payload_from_execution_seed x s sigma) /\
  sigma.`ms3cep_transcript_openings =
    ms3c_payload_coin_driven_transcript_openings
      (ms3c_sim_payload_from_execution_seed x s sigma).
proof.
move=> Hsigma.
have [ss [Hss ->]] := L_ms3c_sim_execution_seed_support_inv x s sigma Hsigma.
clear Hss.
case: ss=> sc sa /=.
rewrite /ms3c_sim_payload_from_execution_seed
  /ms3c_sim_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components /=.
split.
- by rewrite /ms3c_payload_coin_driven_rom_row /ms3c_sim_payload_from_seed
    /ms3c_payload_from_seed_components /ms3c_seed_challenge_coin_driven_rom_row.
by rewrite /ms3c_payload_coin_driven_transcript_openings /ms3c_sim_payload_from_seed
  /ms3c_payload_from_seed_components
  /ms3c_seed_announcement_coin_driven_transcript_openings.
qed.

lemma A_ms3c_real_comparison_payload_matches_execution_seed_law
  (x : ms_public_input) :
  d_ms3c_real_comparison_payload x =
  d_ms3c_real_execution_comparison_payload x.
proof.
rewrite /d_ms3c_real_execution_comparison_payload /d_ms3c_real_execution_seed.
rewrite (dmap_comp ms3c_real_execution_seed_of_payload_seed
  (ms3c_real_payload_from_execution_seed x) (d_ms3c_real_payload_seed x)).
apply eq_dmap_in=> sr _ /=.
case: sr=> sc sa /=.
by rewrite /ms3c_real_payload_from_execution_seed
  /ms3c_real_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_real_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma A_ms3c_sim_comparison_payload_matches_execution_seed_law
  (x : ms_public_input) (s : seed) :
  d_ms3c_sim_comparison_payload x s =
  d_ms3c_sim_execution_comparison_payload x s.
proof.
rewrite /d_ms3c_sim_execution_comparison_payload /d_ms3c_sim_execution_seed.
rewrite (dmap_comp ms3c_sim_execution_seed_of_payload_seed
  (ms3c_sim_payload_from_execution_seed x s) (d_ms3c_sim_payload_seed x s)).
apply eq_dmap_in=> ss _ /=.
case: ss=> sc sa /=.
by rewrite /ms3c_sim_payload_from_execution_seed
  /ms3c_sim_payload_seed_of_execution_seed
  /ms3c_payload_seed_of_execution_seed_package
  /ms3c_sim_execution_seed_of_payload_seed
  /ms3c_execution_seed_package_of_seed_components.
qed.

lemma L_ms3c_real_execution_comparison_payload_law_lossless
  (x : ms_public_input) :
  is_lossless (d_ms3c_real_execution_comparison_payload x).
proof.
by rewrite /d_ms3c_real_execution_comparison_payload; apply dmap_ll;
  apply (L_ms3c_real_execution_seed_law_lossless x).
qed.

lemma L_ms3c_sim_execution_comparison_payload_law_lossless
  (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_execution_comparison_payload x s).
proof.
by rewrite /d_ms3c_sim_execution_comparison_payload; apply dmap_ll;
  apply (L_ms3c_sim_execution_seed_law_lossless x s).
qed.