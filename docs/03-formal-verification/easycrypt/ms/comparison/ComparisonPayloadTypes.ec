require import AllCore.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* Abstract MS-3c seed component types (challenge vs announcement material).
   These are intentionally opaque abstract types until games/transcripts
   fix concrete carriers; **`d_ms3c_*_seed_*`** and **`ms3c_*_payload_from_seed`**
   in **`ComparisonPayloadSeeds.ec`** then refine them. *)
type ms3c_real_seed_challenge.
type ms3c_real_seed_announcement.
type ms3c_sim_seed_challenge.
type ms3c_sim_seed_announcement.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).
