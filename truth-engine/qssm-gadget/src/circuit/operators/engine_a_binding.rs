//! Engine B → Engine A commit-then-open seam binding operator.

#![forbid(unsafe_code)]

use super::super::binding_contract::{BindingLabel, BindingPhase, Nomination, PublicBindingContract};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::ConstraintSystem;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::fmt;
use qssm_utils::hashing::hash_domain;

const DOMAIN_SEAM_COMMIT_V1: &str = "QSSM-SEAM-COMMIT-v1";
const DOMAIN_SEAM_OPEN_V1: &str = "QSSM-SEAM-OPEN-v1";
const DOMAIN_SEAM_BINDING_V1: &str = "QSSM-SEAM-BINDING-v1";

/// Input envelope for Engine-B -> Engine-A commit-then-open seam binding.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EngineABindingInput {
    pub state_root: [u8; 32],
    pub ms_root: [u8; 32],
    pub relation_digest: [u8; 32],
    pub ms_fs_v2_challenge: [u8; 32],
    pub binding_context: [u8; 32],
    pub device_entropy_link: [u8; 32],
    /// Truth digest from [`TruthWitness`] — bound into the seam commitment.
    pub truth_digest: [u8; 32],
    /// Entropy anchor hash — bound into the seam commitment.
    pub entropy_anchor: [u8; 32],
    /// Commitment provided by the proving side and opened by recomputation.
    pub claimed_seam_commitment: [u8; 32],
    /// Must be set to `true` by the caller **after** Engine B verification succeeds.
    /// Synthesis rejects if this is `false`.
    pub require_ms_verified: bool,
}

impl fmt::Debug for EngineABindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineABindingInput")
            .field("state_root", &"[REDACTED]")
            .field("ms_root", &"[REDACTED]")
            .field("relation_digest", &"[REDACTED]")
            .field("ms_fs_v2_challenge", &"[REDACTED]")
            .field("binding_context", &"[REDACTED]")
            .field("device_entropy_link", &"[REDACTED]")
            .field("truth_digest", &"[REDACTED]")
            .field("entropy_anchor", &"[REDACTED]")
            .field("claimed_seam_commitment", &"[REDACTED]")
            .field("require_ms_verified", &self.require_ms_verified)
            .finish()
    }
}

/// Output artifacts emitted by a successful commit-then-open seam check.
#[derive(Debug, Clone)]
pub struct EngineABindingOutput {
    pub seam_commitment_digest: [u8; 32],
    pub seam_open_digest: [u8; 32],
    pub seam_binding_digest: [u8; 32],
}

/// Real Engine-B -> Engine-A seam operator implementing commit-then-open.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineABindingOp;

impl EngineABindingOp {
    /// Commit digest:
    /// `H(DOMAIN_SEAM_COMMIT_V1 || state_root || ms_root || relation_digest || device_entropy_link || binding_context || ms_fs_v2_challenge || truth_digest || entropy_anchor)`.
    #[must_use]
    pub fn commitment_digest(input: &EngineABindingInput) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_COMMIT_V1,
            &[
                input.state_root.as_slice(),
                input.ms_root.as_slice(),
                input.relation_digest.as_slice(),
                input.device_entropy_link.as_slice(),
                input.binding_context.as_slice(),
                input.ms_fs_v2_challenge.as_slice(),
                input.truth_digest.as_slice(),
                input.entropy_anchor.as_slice(),
            ],
        )
    }

    #[must_use]
    pub fn open_digest(input: &EngineABindingInput, seam_commitment: [u8; 32]) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_OPEN_V1,
            &[
                seam_commitment.as_slice(),
                input.ms_fs_v2_challenge.as_slice(),
                input.binding_context.as_slice(),
            ],
        )
    }

    #[must_use]
    pub fn binding_digest(input: &EngineABindingInput, seam_open: [u8; 32]) -> [u8; 32] {
        hash_domain(
            DOMAIN_SEAM_BINDING_V1,
            &[
                seam_open.as_slice(),
                input.ms_root.as_slice(),
                input.state_root.as_slice(),
            ],
        )
    }
}

impl LatticePolyOp for EngineABindingOp {
    type Input = EngineABindingInput;
    type Output = EngineABindingOutput;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> Result<PublicBindingContract, PolyOpError> {
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("ms_fs_v2_challenge".into()),
            Nomination {
                bytes: input.ms_fs_v2_challenge.to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("engine_a_seam_commitment".into()),
            Nomination {
                bytes: input.claimed_seam_commitment.to_vec(),
            },
        ));
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("engine_a_seam_context_digest".into()),
            Nomination {
                bytes: input.binding_context.to_vec(),
            },
        ));
        Ok(c)
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("engine_a_binding");

        if !input.require_ms_verified {
            return Err(PolyOpError::Binding(
                "engine_a seam: require_ms_verified must be true (caller must verify Engine B first)".into(),
            ));
        }

        let zero = [0u8; 32];
        if bool::from(input.state_root.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: state_root is all-zero".into()));
        }
        if bool::from(input.ms_root.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: ms_root is all-zero".into()));
        }
        if bool::from(input.relation_digest.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: relation_digest is all-zero".into()));
        }
        if bool::from(input.device_entropy_link.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: device_entropy_link is all-zero".into()));
        }
        if bool::from(input.binding_context.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: binding_context is all-zero".into()));
        }
        if bool::from(input.ms_fs_v2_challenge.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: ms_fs_v2_challenge is all-zero".into()));
        }
        if bool::from(input.truth_digest.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: truth_digest is all-zero".into()));
        }
        if bool::from(input.entropy_anchor.ct_eq(&zero)) {
            return Err(PolyOpError::Binding("engine_a seam: entropy_anchor is all-zero".into()));
        }

        let recomputed = Self::commitment_digest(&input);
        if !bool::from(recomputed.ct_eq(&input.claimed_seam_commitment)) {
            return Err(PolyOpError::Binding(
                "engine_a seam commit-then-open mismatch".into(),
            ));
        }
        let seam_open = Self::open_digest(&input, recomputed);
        let seam_binding = Self::binding_digest(&input, seam_open);
        Ok(EngineABindingOutput {
            seam_commitment_digest: recomputed,
            seam_open_digest: seam_open,
            seam_binding_digest: seam_binding,
        })
    }
}
