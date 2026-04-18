//! Truth limb v2 operator: truth digest binding from Merkle state root.

#![forbid(unsafe_code)]

use super::super::binding::TruthWitness;
use super::super::binding_contract::{BindingLabel, BindingPhase, Nomination, PublicBindingContract};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::handshake::StateRoot32;
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::ConstraintSystem;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::fmt;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TruthLimbV2Params {
    pub binding_context: [u8; 32],
    pub n: u8,
    pub k: u8,
    pub bit_at_k: u8,
    pub challenge: [u8; 32],
    pub external_entropy: [u8; 32],
    pub external_entropy_included: bool,
    /// Optional **32**-byte digest (e.g. BLAKE3 of device raw noise). When present, it is XOR-mixed
    /// into the entropy floor **before** [`TruthWitness::bind`].
    pub device_entropy_link: Option<[u8; 32]>,
}

impl fmt::Debug for TruthLimbV2Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TruthLimbV2Params")
            .field("binding_context", &"[REDACTED]")
            .field("n", &self.n)
            .field("k", &self.k)
            .field("bit_at_k", &self.bit_at_k)
            .field("challenge", &"[REDACTED]")
            .field("external_entropy", &"[REDACTED]")
            .field("external_entropy_included", &self.external_entropy_included)
            .field("device_entropy_link", &self.device_entropy_link.map(|_| "[REDACTED]"))
            .finish()
    }
}

impl TruthLimbV2Params {
    /// MS Fiat-Shamir **binding entropy** (`qssm_ms` transcript `entropy`): raw **device link** digest when set.
    #[must_use]
    pub fn ms_binding_entropy_digest(&self, fallback: [u8; 32]) -> [u8; 32] {
        self.device_entropy_link.unwrap_or(fallback)
    }
}

#[inline]
pub fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Floor bytes actually fed into [`TruthWitness::bind`] (post device XOR when configured).
#[must_use]
pub fn effective_external_entropy(params: &TruthLimbV2Params) -> [u8; 32] {
    match params.device_entropy_link {
        Some(h) => xor32(params.external_entropy, h),
        None => params.external_entropy,
    }
}

/// Second stage of the truth handshake: truth limb parameters only; input is the Merkle **state root**.
#[derive(Debug, Clone)]
pub struct TruthLimbV2Stage {
    pub params: TruthLimbV2Params,
}

pub type TruthLimbV2Op = TruthLimbV2Stage;
impl TruthLimbV2Stage {
    #[must_use]
    pub fn new(params: TruthLimbV2Params) -> Self {
        Self { params }
    }

    pub fn public_binding_contract_for_root(
        &self,
        state_root: StateRoot32,
    ) -> Result<PublicBindingContract, PolyOpError> {
        let ent = effective_external_entropy(&self.params);
        let w = TruthWitness::bind(
            state_root.0,
            self.params.binding_context,
            self.params.n,
            self.params.k,
            self.params.bit_at_k,
            self.params.challenge,
            ent,
            self.params.external_entropy_included,
        );
        w.validate().map_err(|e| PolyOpError::Binding(format!("TruthWitness: {e}")))?;
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PublicBinding,
            BindingLabel("truth_digest_coeff_binding".into()),
            Nomination {
                bytes: w.digest.to_vec(),
            },
        ));
        Ok(c)
    }
}

impl LatticePolyOp for TruthLimbV2Stage {
    type Input = StateRoot32;
    type Output = TruthWitness;

    fn public_binding_requirements_for_input(&self, input: &Self::Input) -> Result<PublicBindingContract, PolyOpError> {
        self.public_binding_contract_for_root(*input)
    }

    fn synthesize_with_context(
        &self,
        state_root: Self::Input,
        _cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        ctx.set_segment("truth_limb_v2");
        let ent = effective_external_entropy(&self.params);
        if bool::from(ent.ct_eq(&[0u8; 32])) {
            return Err(PolyOpError::Binding(
                "effective external entropy is all-zero (possible XOR cancellation)".into(),
            ));
        }
        let w = TruthWitness::bind(
            state_root.0,
            self.params.binding_context,
            self.params.n,
            self.params.k,
            self.params.bit_at_k,
            self.params.challenge,
            ent,
            self.params.external_entropy_included,
        );
        w.validate().map_err(|e| PolyOpError::Binding(format!("TruthWitness: {e}")))?;
        Ok(w)
    }
}
