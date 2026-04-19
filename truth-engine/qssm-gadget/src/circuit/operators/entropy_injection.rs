//! Raw entropy injection: BLAKE3 digest for reservoir / sovereign device_entropy_link wiring.

#![forbid(unsafe_code)]

use super::super::binding_contract::{
    BindingLabel, BindingPhase, Nomination, PublicBindingContract,
};
use super::super::context::{PolyOpContext, PolyOpError};
use super::super::lattice_polyop::LatticePolyOp;
use super::super::r1cs::ConstraintSystem;

use qssm_utils::{blake3_hash, validate_entropy_full};

#[derive(Debug, Clone)]
pub struct EntropyInjectionOp {
    /// When true, [`validate_entropy_full`] runs on the raw sample (density + χ² when long enough).
    enforce_distribution: bool,
}

impl EntropyInjectionOp {
    /// Production constructor: entropy distribution enforcement is **on** by default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enforce_distribution: true,
        }
    }

    /// Test/demo constructor: skips entropy distribution checks.
    ///
    /// **Not for production use** — weak entropy will be silently accepted.
    #[must_use]
    pub fn new_unvalidated() -> Self {
        Self {
            enforce_distribution: false,
        }
    }
}

impl Default for EntropyInjectionOp {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct EntropyInjectionOutput {
    pub digest: [u8; 32],
    pub raw_len: usize,
}

impl LatticePolyOp for EntropyInjectionOp {
    type Input = Vec<u8>;
    type Output = EntropyInjectionOutput;

    fn public_binding_requirements_for_input(
        &self,
        input: &Self::Input,
    ) -> Result<PublicBindingContract, PolyOpError> {
        let digest = blake3_hash(input);
        let mut c = PublicBindingContract::default();
        c.nominations.push((
            BindingPhase::PreCommit,
            BindingLabel("entropy_device_blake3".into()),
            Nomination {
                bytes: digest.to_vec(),
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
        ctx.set_segment("entropy_injection");
        if self.enforce_distribution {
            validate_entropy_full(&input)?;
        }
        let digest = blake3_hash(&input);
        Ok(EntropyInjectionOutput {
            digest,
            raw_len: input.len(),
        })
    }
}
