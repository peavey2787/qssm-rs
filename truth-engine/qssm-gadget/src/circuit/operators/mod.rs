//! Concrete [`LatticePolyOp`] implementations.

pub mod merkle_parent_blake3;
pub mod truth_limb;
pub mod entropy_injection;
pub mod engine_a_binding;
pub mod ms_ghost_mirror;

pub use merkle_parent_blake3::*;
pub use truth_limb::*;
pub use entropy_injection::*;
pub use engine_a_binding::*;
pub use ms_ghost_mirror::*;

use super::binding_contract::BindingReservoir;
use super::context::{PolyOpContext, PolyOpError};
use super::handshake::TruthPipeOutput;
use super::lattice_polyop::{LatticePolyOp, OpPipe};
use super::r1cs::{ConstraintSystem, VarId, VarKind};

#[derive(Debug, Default)]
struct SilentConstraintSystem {
    next_var: u32,
}

impl ConstraintSystem for SilentConstraintSystem {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }

    fn enforce_xor(&mut self, _x: VarId, _y: VarId, _and_xy: VarId, _z: VarId) {}

    fn enforce_full_adder(
        &mut self,
        _a: VarId,
        _b: VarId,
        _cin: VarId,
        _sum: VarId,
        _cout: VarId,
    ) {
    }

    fn enforce_equal(&mut self, _a: VarId, _b: VarId) {}
}

/// Truth handshake: Merkle parent BLAKE3 compress witness -> truth limb (typed root handoff).
pub type MerkleTruthPipe = OpPipe<MerkleParentBlake3Op, TruthLimbV2Stage>;

#[must_use]
pub fn merkle_truth_pipe(
    merkle: MerkleParentBlake3Op,
    truth_params: TruthLimbV2Params,
) -> MerkleTruthPipe {
    OpPipe::new(merkle, TruthLimbV2Stage::new(truth_params))
}

impl MerkleTruthPipe {
    /// Binding entropy for MS `fs_challenge` when mirroring this pipe.
    #[must_use]
    pub fn ms_binding_entropy_for_fs_challenge(&self, fallback: [u8; 32]) -> [u8; 32] {
        self.second.params.ms_binding_entropy_digest(fallback)
    }

    /// Runs Merkle then truth limb on one cumulative context using the caller-provided constraint
    /// system. **Production callers must supply a real backend** — use [`run_diagnostic`] only for
    /// shape/count analysis where no proving backend is needed.
    pub fn run(
        &self,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<TruthPipeOutput, PolyOpError> {
        let merkle_out = self.first.synthesize_with_context((), cs, ctx)?;
        let c_merged = self
            .first
            .public_binding_requirements_for_input(&())?
            .merge(
                &self
                    .second
                    .public_binding_requirements_for_input(&merkle_out.state_root)?,
            )?;
        let mut reservoir = BindingReservoir::default();
        c_merged.merge_into(&mut reservoir)?;
        let truth_witness =
            self.second
                .synthesize_with_context(merkle_out.state_root, cs, ctx)?;
        let refresh_metadata = ctx.take_refresh_metadata();
        Ok(TruthPipeOutput {
            merkle: merkle_out,
            truth_witness,
            reservoir,
            refresh_metadata,
        })
    }

    /// Diagnostic-only run using a silent (no-op) constraint system.
    ///
    /// Suitable for shape/count analysis and testing. **Not for production proving paths.**
    #[cfg(any(test, feature = "diagnostic"))]
    pub fn run_diagnostic(&self, ctx: &mut PolyOpContext) -> Result<TruthPipeOutput, PolyOpError> {
        let mut cs = SilentConstraintSystem::default();
        self.run(&mut cs, ctx)
    }
}