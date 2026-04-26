//! Candidate zero-knowledge transcript simulation lemmas for QSSM-MS + LE.
//!
//! This module records both:
//!
//! - the legacy MS transcript blocker under the current hidden-value game, and
//! - the canonical publishable path selected for the redesign:
//!   MS v2 Option B plus LE Set B.
//!
//! It keeps the theorem layer honest by separating implemented transcript
//! surfaces, executable simulator artifacts, and the remaining conditional proof
//! obligations.
//!
//! For the legacy MS surface, this module adds the missing executable proof
//! objects that a simulation-based ZK argument would need:
//!
//! - Lemma 1: a witness-free sampler for `(k, n)`
//! - Lemma 2: Fiat-Shamir consistency for simulated transcripts
//! - Lemma 3: commitment + opening simulation for the MS Merkle layer
//!
//! Two strategy families are modeled:
//!
//! - `DistributionCollapse`: sample `(k, n)` from a public marginal over valid
//!   nonce/bit pairs.
//! - `ProgramSimulation`: preserve the real stopping-time scan and program the
//!   transcript around the first successful public nonce.
//!
//! The constructions here are intentionally honest about status. They provide an
//! executable simulator surface for the formal crate, but they do **not** claim
//! that the current end-to-end system already satisfies full ZK. Unmet proof
//! obligations are recorded as exactly that; they are not treated as an
//! impossibility result or a proof that the system is non-ZK.

use crate::{
    lattice::rejection::RejectionSamplingClaim,
    lattice::witness_hiding::WitnessHidingClaim,
    shared::{fiat_shamir::FiatShamirOracle, safety::SimulatorOnly},
    ClaimType,
};
use qssm_gadget::{MERKLE_DEPTH_MS, MERKLE_WIDTH_MS};
use qssm_le::{
    prove_arithmetic, short_vec_to_rq, short_vec_to_rq_bound, verify_lattice, BETA,
    C_POLY_SIZE, C_POLY_SPAN, Commitment, ETA, GAMMA, N, PublicBinding,
    PublicInstance, Q, RqPoly, VerifyingKey, Witness,
    LE_FS_PUBLIC_BINDING_LAYOUT_VERSION,
};
use qssm_utils::{hash_domain, PositionAwareTree, DOMAIN_MS};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use qssm_le::encode_rq_coeffs_le;

const MS_LEAF_COUNT: usize = MERKLE_WIDTH_MS;
const MS_BIT_COUNT: usize = MERKLE_WIDTH_MS / 2;
const DOMAIN_ZK_SIM: &str = "QSSM-ZK-SIM-v1.0";
const MS_BITNESS_QUERY_ANNOUNCEMENT_ONLY_CONTRACT: &str =
    "bitness_query_digest hashes only statement_digest, bit_index, and announcements; it excludes responses and challenge shares.";
const MS_COMPARISON_QUERY_ANNOUNCEMENT_ONLY_CONTRACT: &str =
    "comparison_query_digest hashes only clause announcements; it excludes responses and challenge shares.";
const MS_TRUE_CLAUSE_PUBLIC_POINT_CONTRACT: &str =
    "At the highest differing bit position, every true-clause comparison public point is exactly of the form P = r * H for the corresponding committed blinder r.";
const MS_SCHNORR_REPARAMETERIZATION_CONTRACT: &str =
    "For a fixed public point P = w * H and programmed challenge c, the real Schnorr transcript distribution (alpha, alpha*H, alpha+c*w) is exactly identical to the simulated transcript distribution (z*H-c*P, z) by the bijection z <-> alpha = z - c*w.";


include!("core/types_core.rs");
include!("core/types_theorem.rs");
include!("transcript/lemmas_a.rs");
include!("transcript/lemmas_b.rs");
include!("simulate/simulators.rs");
include!("simulate/simulators_extra.rs");
include!("audit/empirical.rs");
include!("simulate/helpers_ms.rs");
include!("simulate/helpers_le.rs");
include!("core/theorem_core.rs");
include!("core/theorem_prob.rs");
include!("core/theorem_chain.rs");
include!("core/theorem_graph.rs");
include!("audit/closure.rs");
include!("audit/audit.rs");
include!("simulate/redesigned.rs");
include!("transcript/transcript_model.rs");

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
