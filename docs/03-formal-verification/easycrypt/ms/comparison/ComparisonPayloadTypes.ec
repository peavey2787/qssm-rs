require import AllCore List.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes.

(* MS-3c seed component types (challenge vs announcement material).
    The challenge carrier now stores the ROM-facing digest material plus the
    native comparison indices and shares, while the announcement carrier stores
    the concrete announcement points. Real and sim currently share the same
    Phase-1 record shapes; the laws in `ComparisonPayloadSeedTypes.ec` sample
    deterministic records from the native public comparison slice/openings. *)
type ms3c_seed_challenge = {
   ms3csc_stmt_digest : digest;
   ms3csc_true_clause_ix : int;
   ms3csc_false_clause_ixs : int list;
   ms3csc_share_true : scalar;
   ms3csc_share_false : scalar list;
   ms3csc_global_challenge : digest;
   ms3csc_programmed_challenge : digest;
   ms3csc_query_digest : digest;
   ms3csc_rom_coin : scalar;
}.

type ms3c_seed_announcement = {
   ms3csa_ann_true : sch_point;
   ms3csa_ann_false : sch_point list;
   ms3csa_transcript_coin : scalar;
}.

type ms3c_real_seed_challenge = ms3c_seed_challenge.
type ms3c_real_seed_announcement = ms3c_seed_announcement.
type ms3c_sim_seed_challenge = ms3c_seed_challenge.
type ms3c_sim_seed_announcement = ms3c_seed_announcement.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).

op ms3c_phase1_seed_ann_digests (x : ms_public_input) : digest list =
   ms3c_digest_true_announcement (ms3c_public_true_announcement x)
      :: ms3c_digest_false_announcements (ms3c_public_false_announcements x).

op ms3c_phase1_seed_query_digest (x : ms_public_input) : digest =
   ms_comparison_query_digest (ms3c_public_stmt_digest x)
      (ms3c_phase1_seed_ann_digests x).

op ms3c_seed_challenge_with_rom_coin (x : ms_public_input) (rom_coin : scalar) : ms3c_seed_challenge =
   {| ms3csc_stmt_digest = ms3c_public_stmt_digest x;
       ms3csc_true_clause_ix = ms3c_public_true_clause_index x;
       ms3csc_false_clause_ixs = ms3c_public_false_clause_indices x;
       ms3csc_share_true = ms3c_public_true_share x;
       ms3csc_share_false = ms3c_public_false_shares x;
       ms3csc_global_challenge = x.`mspi_comparison_global;
       ms3csc_programmed_challenge = x.`mspi_comparison_global;
       ms3csc_query_digest = ms3c_phase1_seed_query_digest x;
       ms3csc_rom_coin = rom_coin |}.

op ms3c_seed_challenge_programmed_global
   (sc : ms3c_seed_challenge) : digest =
   sc.`ms3csc_programmed_challenge.

op ms3c_seed_announcement_with_transcript_coin
   (x : ms_public_input) (transcript_coin : scalar) : ms3c_seed_announcement =
   {| ms3csa_ann_true = ms3c_public_true_announcement x;
       ms3csa_ann_false = ms3c_public_false_announcements x;
       ms3csa_transcript_coin = transcript_coin |}.

op ms3c_phase1_seed_challenge_from_public_input (x : ms_public_input) : ms3c_seed_challenge =
   ms3c_seed_challenge_with_rom_coin x
     (ms_query_to_scalar (ms3c_phase1_seed_query_digest x)).

op ms3c_phase1_seed_announcement_from_public_input (x : ms_public_input) : ms3c_seed_announcement =
   ms3c_seed_announcement_with_transcript_coin x (ms3c_public_true_share x).

op ms3c_phase1_real_payload_seed_from_public_input (x : ms_public_input) : ms3c_real_payload_seed =
   (ms3c_phase1_seed_challenge_from_public_input x,
    ms3c_phase1_seed_announcement_from_public_input x).

op ms3c_phase1_sim_payload_seed_from_public_input (x : ms_public_input) (_s : seed) : ms3c_sim_payload_seed =
   (ms3c_phase1_seed_challenge_from_public_input x,
    ms3c_phase1_seed_announcement_from_public_input x).

lemma L_ms3c_phase1_seed_challenge_uses_public_surface (x : ms_public_input) :
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_stmt_digest =
      ms3c_public_stmt_digest x /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_true_clause_ix =
      ms3c_public_true_clause_index x /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_false_clause_ixs =
      ms3c_public_false_clause_indices x /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_share_true =
      ms3c_public_true_share x /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_share_false =
      ms3c_public_false_shares x /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_global_challenge =
      x.`mspi_comparison_global /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_programmed_challenge =
      x.`mspi_comparison_global /\
   (ms3c_phase1_seed_challenge_from_public_input x).`ms3csc_query_digest =
      ms3c_phase1_seed_query_digest x.
proof.
rewrite /ms3c_phase1_seed_challenge_from_public_input.
by rewrite /ms3c_seed_challenge_with_rom_coin /=.
qed.

lemma L_ms3c_phase1_seed_announcement_uses_public_surface (x : ms_public_input) :
   (ms3c_phase1_seed_announcement_from_public_input x).`ms3csa_ann_true =
      ms3c_public_true_announcement x /\
   (ms3c_phase1_seed_announcement_from_public_input x).`ms3csa_ann_false =
      ms3c_public_false_announcements x.
proof.
rewrite /ms3c_phase1_seed_announcement_from_public_input.
by rewrite /ms3c_seed_announcement_with_transcript_coin /=.
qed.

lemma L_ms3c_phase1_real_sim_payload_seed_from_public_input
      (x : ms_public_input) (s : seed) :
   ms3c_phase1_sim_payload_seed_from_public_input x s =
      ms3c_phase1_real_payload_seed_from_public_input x.
proof.
by rewrite /ms3c_phase1_sim_payload_seed_from_public_input
                /ms3c_phase1_real_payload_seed_from_public_input.
qed.
