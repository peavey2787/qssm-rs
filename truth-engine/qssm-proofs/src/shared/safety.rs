#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimulatorOnly<T>(T);
/// Simulator capability wrapper.
///
/// Outside `qssm-proofs`, constructors are intentionally unavailable, so
/// downstream crates cannot mint simulator capabilities ad hoc.
///
/// ```compile_fail
/// use qssm_proofs::shared::safety::SimulatorOnly;
/// let _cap = SimulatorOnly::new(42u8);
/// ```
impl<T> SimulatorOnly<T> {
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

/// Capability wrapper for values that are only valid on real prover paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealProverOnly<T>(T);

impl<T> RealProverOnly<T> {
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

/// Capability wrapper for witness-bearing data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessOnly<T>(T);

impl<T> WitnessOnly<T> {
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}
