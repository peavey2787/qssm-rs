require import AllCore.
require import Algebra QssmTypes FS SchnorrBranch TrueClause BitnessOne.
require import ComparisonTypes ComparisonDigests.

(* Abstract MS-3c seed component types (challenge vs announcement material). *)
type ms3c_real_seed_challenge.
type ms3c_real_seed_announcement.
type ms3c_sim_seed_challenge.
type ms3c_sim_seed_announcement.

type ms3c_real_payload_seed = (ms3c_real_seed_challenge * ms3c_real_seed_announcement).
type ms3c_sim_payload_seed = (ms3c_sim_seed_challenge * ms3c_sim_seed_announcement).
