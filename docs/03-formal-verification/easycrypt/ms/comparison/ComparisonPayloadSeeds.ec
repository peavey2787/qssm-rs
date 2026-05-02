require import AllCore List Distr.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests ComparisonPayloadTypes.

(* Seed laws, shape axioms, and payload laws as `dmap` pushforwards of seeds.

   **Discharge path (current gap):** The eight axioms below are not provable here
   because the four component laws **`d_ms3c_{real,sim}_seed_{challenge,announcement}`**
   are abstract **`op`**s (no defining bodies) and **`ms3c_{real,sim}_payload_from_seed`**
   are abstract maps from seeds to payloads.

   - Losslessness (×4): Once each d_ms3c_*_seed_* law is defined as a standard
     EasyCrypt distribution on a finite or full-support carrier (e.g. duniform on
     Finite carriers, dunit, dmap of a lossless ROM read, or a product of such),
     discharge with the corresponding library lemmas (duniform_ll and similar) and
     dprod_ll_auto where the seed law is a product.

   - **Length/index shape (×4):** Once **`ms3c_{real,sim}_payload_from_seed`** are
     defined as the transcript/game constructor building **`ms3c_comparison_clause_payload`**,
     these become proof obligations that the implementation keeps
     **`size ann_false = size share_false`**, **`0 <= true_clause_ix`**, and
     **`size ann_false = size false_clause_ixs`** for every seed tuple.

   **Missing for proofs:** concrete definitions (equations) for the four **`d_ms3c_*`**
   operators and the two **`ms3c_*_payload_from_seed`** operators. *)

op d_ms3c_real_seed_challenge (x : ms_public_input) : ms3c_real_seed_challenge distr.
op d_ms3c_real_seed_announcement (x : ms_public_input) : ms3c_real_seed_announcement distr.

op d_ms3c_sim_seed_challenge (x : ms_public_input) (s : seed) : ms3c_sim_seed_challenge distr.
op d_ms3c_sim_seed_announcement (x : ms_public_input) (s : seed) : ms3c_sim_seed_announcement distr.

op d_ms3c_real_payload_seed (x : ms_public_input) : ms3c_real_payload_seed distr =
  d_ms3c_real_seed_challenge x `*` d_ms3c_real_seed_announcement x.

op d_ms3c_sim_payload_seed (x : ms_public_input) (s : seed) : ms3c_sim_payload_seed distr =
  d_ms3c_sim_seed_challenge x s `*` d_ms3c_sim_seed_announcement x s.

axiom A_ms3c_real_seed_challenge_lossless :
  forall (x : ms_public_input), is_lossless (d_ms3c_real_seed_challenge x).

axiom A_ms3c_real_seed_announcement_lossless :
  forall (x : ms_public_input), is_lossless (d_ms3c_real_seed_announcement x).

axiom A_ms3c_sim_seed_challenge_lossless :
  forall (x : ms_public_input) (s : seed), is_lossless (d_ms3c_sim_seed_challenge x s).

axiom A_ms3c_sim_seed_announcement_lossless :
  forall (x : ms_public_input) (s : seed), is_lossless (d_ms3c_sim_seed_announcement x s).

lemma L_ms3c_real_payload_seed_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_payload_seed x).
proof.
by rewrite /d_ms3c_real_payload_seed; apply dprod_ll_auto;
  [apply (A_ms3c_real_seed_challenge_lossless x) |
   apply (A_ms3c_real_seed_announcement_lossless x)].
qed.

lemma L_ms3c_sim_payload_seed_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_payload_seed x s).
proof.
by rewrite /d_ms3c_sim_payload_seed; apply dprod_ll_auto;
  [apply (A_ms3c_sim_seed_challenge_lossless x s) |
   apply (A_ms3c_sim_seed_announcement_lossless x s)].
qed.

op ms3c_real_payload_from_seed (x : ms_public_input) :
  ms3c_real_payload_seed -> ms3c_real_comparison_payload.

op ms3c_sim_payload_from_seed (x : ms_public_input) (s : seed) :
  ms3c_sim_payload_seed -> ms3c_sim_comparison_payload.

axiom A_ms3c_real_seed_length_shape_valid :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    size (ms3c_real_payload_from_seed x sr).`mscp_share_false.

axiom A_ms3c_real_seed_index_shape_valid :
  forall (x : ms_public_input) (sr : ms3c_real_payload_seed),
    0 <= (ms3c_real_payload_from_seed x sr).`mscp_true_clause_ix /\
    size (ms3c_real_payload_from_seed x sr).`mscp_ann_false =
    size (ms3c_real_payload_from_seed x sr).`mscp_false_clause_ixs.

axiom A_ms3c_sim_seed_length_shape_valid :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    size (ms3c_sim_payload_from_seed x s ss).`mscp_share_false.

axiom A_ms3c_sim_seed_index_shape_valid :
  forall (x : ms_public_input) (s : seed) (ss : ms3c_sim_payload_seed),
    0 <= (ms3c_sim_payload_from_seed x s ss).`mscp_true_clause_ix /\
    size (ms3c_sim_payload_from_seed x s ss).`mscp_ann_false =
    size (ms3c_sim_payload_from_seed x s ss).`mscp_false_clause_ixs.

op d_ms3c_real_comparison_payload (x : ms_public_input) : ms3c_real_comparison_payload distr =
  dmap (d_ms3c_real_payload_seed x) (ms3c_real_payload_from_seed x).

op d_ms3c_sim_comparison_payload (x : ms_public_input) (s : seed) : ms3c_sim_comparison_payload distr =
  dmap (d_ms3c_sim_payload_seed x s) (ms3c_sim_payload_from_seed x s).

lemma L_ms3c_real_comparison_payload_law_lossless (x : ms_public_input) :
  is_lossless (d_ms3c_real_comparison_payload x).
proof.
by rewrite /d_ms3c_real_comparison_payload; apply dmap_ll;
  apply (L_ms3c_real_payload_seed_lossless x).
qed.

lemma L_ms3c_sim_comparison_payload_law_lossless (x : ms_public_input) (s : seed) :
  is_lossless (d_ms3c_sim_comparison_payload x s).
proof.
by rewrite /d_ms3c_sim_comparison_payload; apply dmap_ll;
  apply (L_ms3c_sim_payload_seed_lossless x s).
qed.

op d_ms3c_real_comparison_schedule (x : ms_public_input) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_real_comparison_payload x) ms3c_make_real_clause_surface.

op d_ms3c_sim_comparison_schedule (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  dmap (d_ms3c_sim_comparison_payload x s) ms3c_make_sim_clause_surface.

op d_ms3c_comparison_real_clause (x : ms_public_input) : ms_comparison_clause_surface distr =
  d_ms3c_real_comparison_schedule x.

op d_ms3c_comparison_sim_clause (x : ms_public_input) (s : seed) : ms_comparison_clause_surface distr =
  d_ms3c_sim_comparison_schedule x s.

pred ms_comparison_exact_simulation_equiv (x : ms_public_input) (s : seed) =
  d_ms3c_comparison_real_clause x = d_ms3c_comparison_sim_clause x s.
