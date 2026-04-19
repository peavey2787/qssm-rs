//! Versioned wire-format types for [`ProofBundle`].

use qssm_le::{Commitment, LatticeProof, RqPoly, N};
use qssm_ms::GhostMirrorProof;
use serde::{Deserialize, Serialize};

use crate::context::Proof;

/// Wire-format protocol version (kept for backward compatibility).
pub const PROTOCOL_VERSION: u32 = 1;

// ── Wire format version ──────────────────────────────────────────────
pub(crate) const PROOF_BUNDLE_VERSION: u32 = 1;

/// Versioned, serde-compatible wire format for [`Proof`].
///
/// All byte arrays are hex-encoded; polynomial coefficients are `Vec<u32>`.
/// Use [`ProofBundle::from_proof`] / [`ProofBundle::to_proof`]
/// for lossless round-trip conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProofBundle {
    pub version: u32,
    pub protocol_version: u32,
    // ── MS proof ──
    pub ms_root_hex: String,
    pub ms_n: u8,
    pub ms_k: u8,
    pub ms_bit_at_k: u8,
    pub ms_opened_salt_hex: String,
    pub ms_path_hex: Vec<String>,
    pub ms_challenge_hex: String,
    // ── LE proof ──
    pub le_commitment_coeffs: Vec<u32>,
    pub le_proof_t_coeffs: Vec<u32>,
    pub le_proof_z_coeffs: Vec<u32>,
    pub le_challenge_seed_hex: String,
    // ── External entropy ──
    pub external_entropy_hex: String,
    pub external_entropy_included: bool,
    // ── MS public inputs ──
    pub value: u64,
    pub target: u64,
    pub binding_entropy_hex: String,
}

/// Errors when deserializing a [`ProofBundle`] back into a [`Proof`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WireFormatError {
    #[error("unsupported bundle version {0} (expected {PROOF_BUNDLE_VERSION})")]
    UnsupportedVersion(u32),
    #[error("hex decode failed for field `{field}`: {source}")]
    HexDecode {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("wrong byte length for `{field}`: expected {expected}, got {got}")]
    BadLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("wrong coefficient count for `{field}`: expected {expected}, got {got}")]
    BadCoeffCount {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("invalid MS proof field: {0}")]
    InvalidMsProofField(#[from] qssm_ms::MsError),
}

impl ProofBundle {
    /// Encode an in-memory [`Proof`] into the versioned wire format.
    #[must_use]
    pub fn from_proof(p: &Proof) -> Self {
        Self {
            version: PROOF_BUNDLE_VERSION,
            protocol_version: PROTOCOL_VERSION,
            ms_root_hex: hex::encode(p.ms_root),
            ms_n: p.ms_proof.n(),
            ms_k: p.ms_proof.k(),
            ms_bit_at_k: p.ms_proof.bit_at_k(),
            ms_opened_salt_hex: hex::encode(p.ms_proof.opened_salt()),
            ms_path_hex: p.ms_proof.path().iter().map(hex::encode).collect(),
            ms_challenge_hex: hex::encode(p.ms_proof.challenge()),
            le_commitment_coeffs: p.le_commitment.0 .0.to_vec(),
            le_proof_t_coeffs: p.le_proof.t.0.to_vec(),
            le_proof_z_coeffs: p.le_proof.z.0.to_vec(),
            le_challenge_seed_hex: hex::encode(p.le_proof.challenge_seed),
            external_entropy_hex: hex::encode(p.external_entropy),
            external_entropy_included: p.external_entropy_included,
            value: p.value,
            target: p.target,
            binding_entropy_hex: hex::encode(p.binding_entropy),
        }
    }

    /// Decode the wire format back into an in-memory [`Proof`].
    pub fn to_proof(&self) -> Result<Proof, WireFormatError> {
        if self.version != PROOF_BUNDLE_VERSION {
            return Err(WireFormatError::UnsupportedVersion(self.version));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WireFormatError::UnsupportedVersion(self.protocol_version));
        }
        Ok(Proof {
            ms_root: decode_hash(&self.ms_root_hex, "ms_root_hex")?,
            ms_proof: GhostMirrorProof::new(
                self.ms_n,
                self.ms_k,
                self.ms_bit_at_k,
                decode_hash(&self.ms_opened_salt_hex, "ms_opened_salt_hex")?,
                self.ms_path_hex
                    .iter()
                    .map(|h| decode_hash(h, "ms_path_hex"))
                    .collect::<Result<Vec<_>, _>>()?,
                decode_hash(&self.ms_challenge_hex, "ms_challenge_hex")?,
            )?,
            le_commitment: Commitment(RqPoly(vec_to_poly(
                &self.le_commitment_coeffs,
                "le_commitment_coeffs",
            )?)),
            le_proof: LatticeProof {
                t: RqPoly(vec_to_poly(&self.le_proof_t_coeffs, "le_proof_t_coeffs")?),
                z: RqPoly(vec_to_poly(&self.le_proof_z_coeffs, "le_proof_z_coeffs")?),
                challenge_seed: decode_hash(&self.le_challenge_seed_hex, "le_challenge_seed_hex")?,
            },
            external_entropy: decode_hash(&self.external_entropy_hex, "external_entropy_hex")?,
            external_entropy_included: self.external_entropy_included,
            value: self.value,
            target: self.target,
            binding_entropy: decode_hash(&self.binding_entropy_hex, "binding_entropy_hex")?,
        })
    }
}

fn decode_hash(hex_str: &str, field: &'static str) -> Result<[u8; 32], WireFormatError> {
    let bytes =
        hex::decode(hex_str).map_err(|source| WireFormatError::HexDecode { field, source })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| WireFormatError::BadLength {
        field,
        expected: 32,
        got: bytes.len(),
    })
}

fn vec_to_poly(v: &[u32], field: &'static str) -> Result<[u32; N], WireFormatError> {
    <[u32; N]>::try_from(v).map_err(|_| WireFormatError::BadCoeffCount {
        field,
        expected: N,
        got: v.len(),
    })
}
