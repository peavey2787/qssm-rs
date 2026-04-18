//! Phased binding nominations: [`BindingReservoir`] and [`PublicBindingContract`].

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use super::context::PolyOpError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingPhase {
    PreCommit = 0,
    PublicBinding = 1,
    Aux = 2,
}

/// Label for `BTreeMap` nominations within a phase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingLabel(pub String);

#[derive(Debug, Clone)]
pub struct Nomination {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct BindingReservoir {
    /// Per-phase, ordered map of auxiliary nominations (canonical `Ord` on label).
    pub by_phase: BTreeMap<BindingPhase, BTreeMap<BindingLabel, Nomination>>,
}

impl BindingReservoir {
    pub fn nominate(
        &mut self,
        phase: BindingPhase,
        label: BindingLabel,
        bytes: Vec<u8>,
    ) -> Result<(), PolyOpError> {
        let phase_map = self.by_phase.entry(phase).or_default();
        if phase_map
            .insert(label.clone(), Nomination { bytes })
            .is_some()
        {
            return Err(PolyOpError::PhaseSlotConflict(format!(
                "duplicate nomination label {:?}",
                label.0
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public binding contract (per-op declaration)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct PublicBindingContract {
    pub nominations: Vec<(BindingPhase, BindingLabel, Nomination)>,
}

impl PublicBindingContract {
    /// Concatenate nominations in order **`self`** then **`other`**, rejecting duplicate **`(phase, label)`**.
    pub fn merge(&self, other: &Self) -> Result<Self, PolyOpError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for (p, l, n) in self.nominations.iter().chain(other.nominations.iter()) {
            let key = (*p, l.0.clone());
            if !seen.insert(key) {
                return Err(PolyOpError::PhaseSlotConflict(format!(
                    "duplicate (phase, label) {:?} {:?}",
                    p, l.0
                )));
            }
            out.push((*p, l.clone(), n.clone()));
        }
        Ok(Self { nominations: out })
    }

    pub fn merge_into(&self, reservoir: &mut BindingReservoir) -> Result<(), PolyOpError> {
        for (phase, label, nom) in &self.nominations {
            reservoir.nominate(*phase, label.clone(), nom.bytes.clone())?;
        }
        Ok(())
    }
}
