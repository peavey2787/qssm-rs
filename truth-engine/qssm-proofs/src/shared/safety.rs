#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimulatorOnly<T>(T);

impl<T> SimulatorOnly<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}
