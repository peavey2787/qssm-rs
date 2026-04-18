//! Platform/backend data collection paths (hardware-facing).

pub mod sensor;
pub mod time;

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows_tsc;
