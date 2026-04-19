//! Handshake artifact / output structs and [`EngineAPublicJson`] serialization.

#![forbid(unsafe_code)]

use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;

use super::binding::TruthWitness;
use super::binding_contract::{BindingReservoir, PublicBindingContract};
use super::context::{CopyRefreshMeta, PolyOpError};
use crate::primitives::blake3_compress::MerkleParentHashWitness;

use qssm_utils::hashing::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION;

/// Must equal [`qssm_utils::hashing::LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`].
pub const TRANSCRIPT_MAP_LAYOUT_VERSION: u32 = 1;

const _: () = assert!(
    TRANSCRIPT_MAP_LAYOUT_VERSION == LE_FS_PUBLIC_BINDING_LAYOUT_VERSION,
    "bump TRANSCRIPT_MAP_LAYOUT_VERSION when TranscriptMap / engine_a_public layout changes, then sync qssm-utils LE_FS_PUBLIC_BINDING_LAYOUT_VERSION with qssm-le commit.rs"
);

/// JSON keys under `engine_a_public` in **canonical wire order** (digest mode for L2 handshake).
pub const ENGINE_A_PUBLIC_KEYS_IN_ORDER: &[&str] = &["message_limb_u30", "digest_coeff_vector_u4"];

use super::binding::DIGEST_COEFF_VECTOR_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateRoot32(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct MerkleParentBlake3Output {
    pub witness: MerkleParentHashWitness,
    pub state_root: StateRoot32,
    pub contract: PublicBindingContract,
}

#[derive(Debug)]
pub struct TruthPipeOutput {
    pub merkle: MerkleParentBlake3Output,
    pub truth_witness: TruthWitness,
    pub reservoir: BindingReservoir,
    /// R1CS copy-refreshes from Merkle (and later stages if any); taken from [`PolyOpContext`] at end of [`OpPipe::run`].
    pub refresh_metadata: Vec<CopyRefreshMeta>,
}

#[derive(Debug, Clone)]
pub struct EngineAPublicJson {
    pub message_limb_u30: u64,
    pub digest_coeff_vector_u4: Vec<u32>,
}

impl Serialize for EngineAPublicJson {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut m = serializer.serialize_map(Some(ENGINE_A_PUBLIC_KEYS_IN_ORDER.len()))?;
        m.serialize_entry("message_limb_u30", &self.message_limb_u30)?;
        m.serialize_entry("digest_coeff_vector_u4", &self.digest_coeff_vector_u4)?;
        m.end()
    }
}

impl EngineAPublicJson {
    pub fn from_witness(w: &TruthWitness) -> Self {
        Self {
            message_limb_u30: w.message_limb,
            digest_coeff_vector_u4: w.digest_coeff_vector.to_vec(),
        }
    }

    /// Validates key order and coeff count against [`TranscriptMap`].
    pub fn validate_transcript_map(&self) -> Result<(), PolyOpError> {
        if self.digest_coeff_vector_u4.len() != DIGEST_COEFF_VECTOR_SIZE {
            return Err(PolyOpError::TranscriptMapViolation(format!(
                "digest_coeff_vector_u4 len {} want {}",
                self.digest_coeff_vector_u4.len(),
                DIGEST_COEFF_VECTOR_SIZE
            )));
        }
        for &k in ENGINE_A_PUBLIC_KEYS_IN_ORDER {
            let ok = match k {
                "message_limb_u30" => true,
                "digest_coeff_vector_u4" => true,
                _ => false,
            };
            if !ok {
                return Err(PolyOpError::TranscriptMapViolation(format!(
                    "unknown engine_a_public key {k}"
                )));
            }
        }
        Ok(())
    }

    /// JSON value with **canonical key order** (see [`Serialize`] impl).
    ///
    /// Returns `Err` if serialization fails (should not happen with well-formed data).
    pub fn to_ordered_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}
