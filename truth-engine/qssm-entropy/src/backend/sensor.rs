//! Optional IMU payload: [`None`] on desktop (no stack-heavy inline buffer), dense [`SmallVec`] on mobile.

use smallvec::SmallVec;

/// Inline capacity for a typical short IMU burst before spilling to the heap.
pub const SENSOR_INLINE_CAP: usize = 256;

/// Raw accelerometer / motion bytes packed by the embedder (e.g. little-endian axis samples).
///
/// Use [`SensorEntropy::none`] on desktop or when no sensor is present: only the `Option`
/// discriminant is stored—no heap allocation and no large fixed inline array on every
/// [`crate::Heartbeat`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorEntropy(Option<SmallVec<[u8; SENSOR_INLINE_CAP]>>);

impl SensorEntropy {
    /// No sensor path (e.g. Ryzen desktop without IMU wiring).
    #[must_use]
    pub fn none() -> Self {
        Self(None)
    }

    /// Wrap a packed payload (may spill to heap if `bytes` exceeds [`SENSOR_INLINE_CAP`]).
    #[must_use]
    pub fn from_smallvec(bytes: SmallVec<[u8; SENSOR_INLINE_CAP]>) -> Self {
        if bytes.is_empty() {
            Self(None)
        } else {
            Self(Some(bytes))
        }
    }

    /// Copy slice into a [`SmallVec`] and wrap; empty slice → [`SensorEntropy::none`].
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            Self(None)
        } else {
            Self(Some(SmallVec::from_slice(bytes)))
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_none_or(|v| v.is_empty())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_deref().unwrap_or(&[])
    }
}

impl Default for SensorEntropy {
    fn default() -> Self {
        Self::none()
    }
}

impl AsRef<[u8]> for SensorEntropy {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
