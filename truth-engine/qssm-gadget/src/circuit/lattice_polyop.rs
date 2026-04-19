//! [`LatticePolyOp`] trait, [`OpPipe`] generic composition, and [`LatticePolyOpThen`] extension.

#![forbid(unsafe_code)]

use super::binding_contract::PublicBindingContract;
use super::context::{PolyOpContext, PolyOpError};
use super::r1cs::ConstraintSystem;

pub trait LatticePolyOp: Send + Sync {
    type Input;
    type Output;

    /// Static / input-agnostic nominations (default empty).
    fn get_public_binding_requirements(&self) -> Result<PublicBindingContract, PolyOpError> {
        Ok(PublicBindingContract::default())
    }

    /// Nominations that may depend on **`input`** (e.g. Merkle root-dependent paths in a later stage).
    ///
    /// For [`OpPipe`], nominations from **`B`** are merged inside `synthesize_with_context` after
    /// **`A::Output`** is known; this method on `OpPipe` returns only **`A`**'s contract (see doc on [`OpPipe`]).
    fn public_binding_requirements_for_input(
        &self,
        input: &Self::Input,
    ) -> Result<PublicBindingContract, PolyOpError> {
        let _ = input;
        self.get_public_binding_requirements()
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError>;
}

// ---------------------------------------------------------------------------
// OpPipe — generic pair; shared `cs` + cumulative `ctx` across both stages.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OpPipe<A, B> {
    pub first: A,
    pub second: B,
}

impl<A, B> OpPipe<A, B> {
    #[must_use]
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A, B, I, M, O> LatticePolyOp for OpPipe<A, B>
where
    A: LatticePolyOp<Input = I, Output = M>,
    B: LatticePolyOp<Input = M, Output = O>,
{
    type Input = I;
    type Output = O;

    fn public_binding_requirements_for_input(
        &self,
        input: &Self::Input,
    ) -> Result<PublicBindingContract, PolyOpError> {
        self.first.public_binding_requirements_for_input(input)
    }

    fn synthesize_with_context(
        &self,
        input: Self::Input,
        cs: &mut impl ConstraintSystem,
        ctx: &mut PolyOpContext,
    ) -> Result<Self::Output, PolyOpError> {
        let mid = self.first.synthesize_with_context(input, cs, ctx)?;
        self.second.synthesize_with_context(mid, cs, ctx)
    }
}

pub trait LatticePolyOpThen: LatticePolyOp + Sized {
    fn then<B>(self, second: B) -> OpPipe<Self, B>
    where
        B: LatticePolyOp<Input = Self::Output>,
    {
        OpPipe::new(self, second)
    }
}

impl<T: LatticePolyOp + Sized> LatticePolyOpThen for T {}
