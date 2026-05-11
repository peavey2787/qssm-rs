require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes ComparisonPayloadSeeds.
require import ComparisonPayloadSupportTypes.

(* Challenge-share obligation predicates and packaging lemmas. *)

pred ms3c_ax_payload_challenge_shares_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_challenge_shares_match pr ps.

pred ms3c_ax_payload_true_challenge_share_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_true_challenge_share_match pr ps.

pred ms3c_ax_payload_false_challenge_shares_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_false_challenge_shares_match pr ps.

pred ms3c_ax_payload_challenge_share_lengths_match (x : ms_public_input) (s : seed) =
  forall (pr : ms3c_real_comparison_payload) (ps : ms3c_sim_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms3c_sim_payload_on_support x s ps =>
    ms3c_payload_pair_challenge_share_lengths_match pr ps.

(* `ms3c_ax_payload_challenge_share_lengths_match` is not used in the proof body
   below: list equality from the false-branch fragment implies matching lengths.
   The separate length obligation is for incremental game discharges (e.g. shape
   before pointwise list agreement). *)
lemma L_ms3c_ax_payload_challenge_shares_match_from_fragments
  (x : ms_public_input) (s : seed) :
  ms3c_ax_payload_true_challenge_share_match x s =>
  ms3c_ax_payload_false_challenge_shares_match x s =>
  ms3c_ax_payload_challenge_share_lengths_match x s =>
  ms3c_ax_payload_challenge_shares_match x s.
proof.
move=> Ht Hf _Hlen pr ps Hpr Hps.
have Ht' := Ht pr ps Hpr Hps.
have Hf' := Hf pr ps Hpr Hps.
rewrite /ms3c_payload_pair_challenge_shares_match.
by split.
qed.

pred ms3c_ax_payload_false_clauses_simulated (x : ms_public_input) (s : seed) =
  (forall (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_false_clause_simulated (ms3c_make_real_clause_surface pr)) /\
  (forall (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_false_clause_simulated (ms3c_make_sim_clause_surface ps)).

pred ms3c_ax_payload_true_clause_simulated (x : ms_public_input) (s : seed) =
  (forall (vb tb : bool list) (p : int) (r : scalar) (pr : ms3c_real_comparison_payload),
    ms3c_real_payload_on_support x pr =>
    ms_true_clause_simulates_from_blinder_points vb tb p r (ms3c_make_real_clause_surface pr) =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder
      (ms3c_make_real_clause_surface pr).`mscc_ann_true true r) /\
  (forall (vb tb : bool list) (p : int) (r : scalar) (ps : ms3c_sim_comparison_payload),
    ms3c_sim_payload_on_support x s ps =>
    ms_true_clause_simulates_from_blinder_points vb tb p r (ms3c_make_sim_clause_surface ps) =>
    ms_true_clause_position vb tb p =>
    ms_clause_public_point_matches_blinder
      (ms3c_make_sim_clause_surface ps).`mscc_ann_true true r).
