//! Platform/backend data collection paths (hardware-facing).

pub mod sensor;
pub mod time;

/// Cross-platform hardware jitter harvester.
///
/// Supported on x86, x86_64 (TSC), and aarch64 (CNTVCT_EL0).
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
pub mod jitter;
