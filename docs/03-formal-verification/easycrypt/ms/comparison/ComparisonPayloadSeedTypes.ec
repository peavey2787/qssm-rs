require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonPayloadTypes.

(* MS-3c seed component laws (d_ms3c real/sim seed_challenge and
  seed_announcement) and joint seed distributions.
  Payload-facing fields stay fixed to the native public comparison slice and
  openings, while latent ROM/transcript coin fields are now sampled from
  `duni_scalar`; see module comment in ComparisonPayloadSeeds.ec (facade) for
  the current discharge narrative. *)

(* Real challenge-side law: sample a latent ROM coin while keeping the
  payload-facing challenge fields pinned to the native public surface. *)
op d_ms3c_real_seed_challenge (x : ms_public_input) : ms3c_real_seed_challenge distr =
  dmap duni_scalar (ms3c_seed_challenge_with_rom_coin x).

(* Real announcement-side law: sample a latent transcript coin while keeping
  the public announcement surface fixed. *)
op d_ms3c_real_seed_announcement (x : ms_public_input) : ms3c_real_seed_announcement distr =
  dmap duni_scalar (ms3c_seed_announcement_with_transcript_coin x).

(* Sim challenge-side law: same sampled latent ROM coin shape. The external sim
  seed argument remains for API stability until richer simulator coins land. *)
op d_ms3c_sim_seed_challenge (x : ms_public_input) (_s : seed) : ms3c_sim_seed_challenge distr =
  dmap duni_scalar (ms3c_seed_challenge_with_rom_coin x).

(* Sim announcement-side law: same sampled latent transcript-coin shape. *)
op d_ms3c_sim_seed_announcement (x : ms_public_input) (_s : seed) : ms3c_sim_seed_announcement distr =
  dmap duni_scalar (ms3c_seed_announcement_with_transcript_coin x).

op d_ms3c_real_payload_seed (x : ms_public_input) : ms3c_real_payload_seed distr =
  d_ms3c_real_seed_challenge x `*` d_ms3c_real_seed_announcement x.

op d_ms3c_sim_payload_seed (x : ms_public_input) (s : seed) : ms3c_sim_payload_seed distr =
  d_ms3c_sim_seed_challenge x s `*` d_ms3c_sim_seed_announcement x s.

lemma L_ms3c_real_seed_challenge_on_support_public_surface
  (x : ms_public_input) (sc : ms3c_real_seed_challenge) :
  sc \in d_ms3c_real_seed_challenge x =>
  sc.`ms3csc_stmt_digest = ms3c_public_stmt_digest x /\
  sc.`ms3csc_true_clause_ix = ms3c_public_true_clause_index x /\
  sc.`ms3csc_false_clause_ixs = ms3c_public_false_clause_indices x /\
  sc.`ms3csc_share_true = ms3c_public_true_share x /\
  sc.`ms3csc_share_false = ms3c_public_false_shares x /\
  sc.`ms3csc_global_challenge = x.`mspi_comparison_global /\
  sc.`ms3csc_programmed_challenge = x.`mspi_comparison_global /\
  sc.`ms3csc_query_digest = ms3c_phase1_seed_query_digest x.
proof.
move=> Hsc.
rewrite /d_ms3c_real_seed_challenge in Hsc.
case/supp_dmap: Hsc => rom_coin [_ Hsc].
rewrite Hsc /ms3c_seed_challenge_with_rom_coin /=.
by split=> //; split=> //; split=> //; split=> //; split=> //; split=> //; split.
qed.

lemma L_ms3c_sim_seed_challenge_on_support_public_surface
  (x : ms_public_input) (s : seed) (sc : ms3c_sim_seed_challenge) :
  sc \in d_ms3c_sim_seed_challenge x s =>
  sc.`ms3csc_stmt_digest = ms3c_public_stmt_digest x /\
  sc.`ms3csc_true_clause_ix = ms3c_public_true_clause_index x /\
  sc.`ms3csc_false_clause_ixs = ms3c_public_false_clause_indices x /\
  sc.`ms3csc_share_true = ms3c_public_true_share x /\
  sc.`ms3csc_share_false = ms3c_public_false_shares x /\
  sc.`ms3csc_global_challenge = x.`mspi_comparison_global /\
  sc.`ms3csc_programmed_challenge = x.`mspi_comparison_global /\
  sc.`ms3csc_query_digest = ms3c_phase1_seed_query_digest x.
proof.
move=> Hsc.
rewrite /d_ms3c_sim_seed_challenge in Hsc.
case/supp_dmap: Hsc => rom_coin [_ Hsc].
rewrite Hsc /ms3c_seed_challenge_with_rom_coin /=.
by split=> //; split=> //; split=> //; split=> //; split=> //; split=> //; split.
qed.

lemma L_ms3c_real_seed_announcement_on_support_public_surface
  (x : ms_public_input) (sa : ms3c_real_seed_announcement) :
  sa \in d_ms3c_real_seed_announcement x =>
  sa.`ms3csa_ann_true = ms3c_public_true_announcement x /\
  sa.`ms3csa_ann_false = ms3c_public_false_announcements x.
proof.
move=> Hsa.
rewrite /d_ms3c_real_seed_announcement in Hsa.
case/supp_dmap: Hsa => transcript_coin [_ Hsa].
rewrite Hsa /ms3c_seed_announcement_with_transcript_coin /=.
by split.
qed.

lemma L_ms3c_sim_seed_announcement_on_support_public_surface
  (x : ms_public_input) (s : seed) (sa : ms3c_sim_seed_announcement) :
  sa \in d_ms3c_sim_seed_announcement x s =>
  sa.`ms3csa_ann_true = ms3c_public_true_announcement x /\
  sa.`ms3csa_ann_false = ms3c_public_false_announcements x.
proof.
move=> Hsa.
rewrite /d_ms3c_sim_seed_announcement in Hsa.
case/supp_dmap: Hsa => transcript_coin [_ Hsa].
rewrite Hsa /ms3c_seed_announcement_with_transcript_coin /=.
by split.
qed.

lemma L_ms3c_real_seed_challenge_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_seed_challenge x).
proof.
by rewrite /d_ms3c_real_seed_challenge; apply dmap_ll; apply duni_scalar_lossless.
qed.

lemma L_ms3c_sim_seed_challenge_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_seed_challenge x s).
proof.
by rewrite /d_ms3c_sim_seed_challenge; apply dmap_ll; apply duni_scalar_lossless.
qed.

lemma L_ms3c_real_seed_announcement_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_seed_announcement x).
proof.
by rewrite /d_ms3c_real_seed_announcement; apply dmap_ll; apply duni_scalar_lossless.
qed.

lemma L_ms3c_sim_seed_announcement_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_seed_announcement x s).
proof.
by rewrite /d_ms3c_sim_seed_announcement; apply dmap_ll; apply duni_scalar_lossless.
qed.

lemma L_ms3c_real_payload_seed_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_payload_seed x).
proof.
by rewrite /d_ms3c_real_payload_seed; apply dprod_ll_auto;
  [apply (L_ms3c_real_seed_challenge_lossless x) |
   apply (L_ms3c_real_seed_announcement_lossless x)].
qed.

lemma L_ms3c_sim_payload_seed_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_payload_seed x s).
proof.
by rewrite /d_ms3c_sim_payload_seed; apply dprod_ll_auto;
  [apply (L_ms3c_sim_seed_challenge_lossless x s) |
   apply (L_ms3c_sim_seed_announcement_lossless x s)].
qed.
