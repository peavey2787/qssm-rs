//! Global on/off switch for hardware harvesting (e.g. Tauri UI toggle).
//! When disabled, [`super::harvest`] returns [`crate::HeError::HarvestDisabled`] immediately.

use std::sync::atomic::{AtomicBool, Ordering};

static HARDWARE_HARVEST_ENABLED: AtomicBool = AtomicBool::new(true);

/// When `false`, [`crate::harvest`] / [`crate::harvest_with_sensor`] return [`crate::HeError::HarvestDisabled`].
#[inline]
pub fn set_hardware_harvest_enabled(enabled: bool) {
    HARDWARE_HARVEST_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Current harvest gate (default: enabled).
#[inline]
#[must_use]
pub fn hardware_harvest_enabled() -> bool {
    HARDWARE_HARVEST_ENABLED.load(Ordering::SeqCst)
}

#[inline]
pub(crate) fn guard_harvest_enabled() -> Result<(), crate::HeError> {
    if hardware_harvest_enabled() {
        Ok(())
    } else {
        Err(crate::HeError::HarvestDisabled)
    }
}
