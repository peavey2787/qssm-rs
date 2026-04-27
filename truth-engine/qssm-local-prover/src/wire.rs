//! Versioned wire-format types for [`ProofBundle`] (MS v2 predicate-only).

use qssm_le::{Commitment, LatticeProof, RqPoly, N};
use qssm_ms::{
    BitnessProofV2, ComparisonClauseProofV2, ComparisonProofV2, EqualitySubproofV2,
    PredicateOnlyProofV2, PredicateOnlyStatementV2, ValueCommitmentV2, V2_BIT_COUNT,
};
use serde::{Deserialize, Serialize};

use crate::context::Proof;

/// Wire-format protocol version (bumped with MS v2 bundle schema).
pub const PROTOCOL_VERSION: u32 = 2;

pub(crate) const PROOF_BUNDLE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsV2BitnessWire {
    pub announce_zero_hex: String,
    pub announce_one_hex: String,
    pub challenge_zero_hex: String,
    pub challenge_one_hex: String,
    pub response_zero_hex: String,
    pub response_one_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsV2EqualityWire {
    pub announcement_hex: String,
    pub response_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsV2ComparisonClauseWire {
    pub challenge_share_hex: String,
    pub subproofs: Vec<MsV2EqualityWire>,
}

/// Versioned, serde-compatible wire format for [`Proof`].
///
/// All byte arrays are hex-encoded; polynomial coefficients are `Vec<u32>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ProofBundle {
    pub version: u32,
    pub protocol_version: u32,
    pub ms_v2_target: u64,
    pub ms_v2_binding_entropy_hex: String,
    pub ms_v2_binding_context_hex: String,
    pub ms_v2_context_hex: String,
    pub ms_v2_bit_commitments_hex: Vec<String>,
    pub ms_v2_proof_result: bool,
    pub ms_v2_proof_statement_digest_hex: String,
    pub ms_v2_bitness_proofs: Vec<MsV2BitnessWire>,
    pub ms_v2_comparison_clauses: Vec<MsV2ComparisonClauseWire>,
    pub le_commitment_coeffs: Vec<u32>,
    pub le_proof_t_coeffs: Vec<u32>,
    pub le_proof_z_coeffs: Vec<u32>,
    pub le_challenge_seed_hex: String,
    pub external_entropy_hex: String,
    pub external_entropy_included: bool,
    pub value: u64,
    pub binding_entropy_hex: String,
}

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
    #[error("invalid MS v2 field: {0}")]
    InvalidMsProofField(#[from] qssm_ms::MsError),
    #[error("MS v2 wire inconsistency: {0}")]
    MsV2Inconsistent(&'static str),
}

impl ProofBundle {
    #[must_use]
    pub fn from_proof(p: &Proof) -> Self {
        let st = p.ms_statement();
        let bitness: Vec<MsV2BitnessWire> = p
            .ms_proof()
            .bitness_proofs()
            .iter()
            .map(|bp| MsV2BitnessWire {
                announce_zero_hex: hex::encode(bp.announce_zero_bytes()),
                announce_one_hex: hex::encode(bp.announce_one_bytes()),
                challenge_zero_hex: hex::encode(bp.challenge_zero_bytes()),
                challenge_one_hex: hex::encode(bp.challenge_one_bytes()),
                response_zero_hex: hex::encode(bp.response_zero_bytes()),
                response_one_hex: hex::encode(bp.response_one_bytes()),
            })
            .collect();
        let clauses: Vec<MsV2ComparisonClauseWire> = p
            .ms_proof()
            .comparison_proof()
            .clauses_slice()
            .iter()
            .map(|cl| MsV2ComparisonClauseWire {
                challenge_share_hex: hex::encode(cl.challenge_share_bytes()),
                subproofs: cl
                    .subproofs_slice()
                    .iter()
                    .map(|sp| MsV2EqualityWire {
                        announcement_hex: hex::encode(sp.announcement_bytes()),
                        response_hex: hex::encode(sp.response_bytes()),
                    })
                    .collect(),
            })
            .collect();
        let be = *st.binding_entropy();
        Self {
            version: PROOF_BUNDLE_VERSION,
            protocol_version: PROTOCOL_VERSION,
            ms_v2_target: st.target(),
            ms_v2_binding_entropy_hex: hex::encode(be),
            ms_v2_binding_context_hex: hex::encode(st.binding_context()),
            ms_v2_context_hex: hex::encode(st.context()),
            ms_v2_bit_commitments_hex: st
                .commitment()
                .bit_commitments()
                .iter()
                .map(hex::encode)
                .collect(),
            ms_v2_proof_result: p.ms_proof().result(),
            ms_v2_proof_statement_digest_hex: hex::encode(p.ms_proof().statement_digest()),
            ms_v2_bitness_proofs: bitness,
            ms_v2_comparison_clauses: clauses,
            le_commitment_coeffs: p.le_commitment().0 .0.to_vec(),
            le_proof_t_coeffs: p.le_proof().t.0.to_vec(),
            le_proof_z_coeffs: p.le_proof().z.0.to_vec(),
            le_challenge_seed_hex: hex::encode(p.le_proof().challenge_seed),
            external_entropy_hex: hex::encode(p.external_entropy()),
            external_entropy_included: p.external_entropy_included(),
            value: p.value(),
            binding_entropy_hex: hex::encode(be),
        }
    }

    pub fn to_proof(&self) -> Result<Proof, WireFormatError> {
        if self.version != PROOF_BUNDLE_VERSION {
            return Err(WireFormatError::UnsupportedVersion(self.version));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WireFormatError::UnsupportedVersion(self.protocol_version));
        }
        let be_a = decode_hash(&self.ms_v2_binding_entropy_hex, "ms_v2_binding_entropy_hex")?;
        let be_b = decode_hash(&self.binding_entropy_hex, "binding_entropy_hex")?;
        if be_a != be_b {
            return Err(WireFormatError::MsV2Inconsistent(
                "binding_entropy_hex must match ms_v2_binding_entropy_hex",
            ));
        }
        if self.ms_v2_bit_commitments_hex.len() != V2_BIT_COUNT {
            return Err(WireFormatError::BadLength {
                field: "ms_v2_bit_commitments_hex",
                expected: V2_BIT_COUNT,
                got: self.ms_v2_bit_commitments_hex.len(),
            });
        }
        if self.ms_v2_bitness_proofs.len() != V2_BIT_COUNT {
            return Err(WireFormatError::BadLength {
                field: "ms_v2_bitness_proofs",
                expected: V2_BIT_COUNT,
                got: self.ms_v2_bitness_proofs.len(),
            });
        }
        let bit_commitments: Vec<[u8; 32]> = self
            .ms_v2_bit_commitments_hex
            .iter()
            .map(|h| decode_hash(h, "ms_v2_bit_commitments_hex"))
            .collect::<Result<Vec<_>, _>>()?;
        let commitment = ValueCommitmentV2::new(bit_commitments)?;
        let binding_ctx =
            decode_hash(&self.ms_v2_binding_context_hex, "ms_v2_binding_context_hex")?;
        let context =
            hex::decode(&self.ms_v2_context_hex).map_err(|source| WireFormatError::HexDecode {
                field: "ms_v2_context_hex",
                source,
            })?;
        let statement = PredicateOnlyStatementV2::new(
            commitment,
            self.ms_v2_target,
            be_a,
            binding_ctx,
            context,
        );
        let bitness: Vec<BitnessProofV2> = self
            .ms_v2_bitness_proofs
            .iter()
            .map(decode_bitness_wire)
            .collect::<Result<_, _>>()?;
        let clauses: Vec<ComparisonClauseProofV2> = self
            .ms_v2_comparison_clauses
            .iter()
            .map(decode_clause_wire)
            .collect::<Result<_, _>>()?;
        let comparison = ComparisonProofV2::from_clauses(clauses);
        let statement_digest = decode_hash(
            &self.ms_v2_proof_statement_digest_hex,
            "ms_v2_proof_statement_digest_hex",
        )?;
        let ms_proof = PredicateOnlyProofV2::from_wire_parts(
            self.ms_v2_proof_result,
            statement_digest,
            bitness,
            comparison,
            self.ms_v2_target,
        )?;
        let cd = statement.commitment().digest();
        Ok(Proof::new(
            cd,
            statement,
            ms_proof,
            Commitment(RqPoly(vec_to_poly(
                &self.le_commitment_coeffs,
                "le_commitment_coeffs",
            )?)),
            LatticeProof {
                t: RqPoly(vec_to_poly(&self.le_proof_t_coeffs, "le_proof_t_coeffs")?),
                z: RqPoly(vec_to_poly(&self.le_proof_z_coeffs, "le_proof_z_coeffs")?),
                challenge_seed: decode_hash(&self.le_challenge_seed_hex, "le_challenge_seed_hex")?,
            },
            decode_hash(&self.external_entropy_hex, "external_entropy_hex")?,
            self.external_entropy_included,
            self.value,
        ))
    }
}

fn decode_bitness_wire(w: &MsV2BitnessWire) -> Result<BitnessProofV2, WireFormatError> {
    Ok(BitnessProofV2::from_wire(
        decode_hash(&w.announce_zero_hex, "ms_v2_bitness.announce_zero_hex")?,
        decode_hash(&w.announce_one_hex, "ms_v2_bitness.announce_one_hex")?,
        decode_hash(&w.challenge_zero_hex, "ms_v2_bitness.challenge_zero_hex")?,
        decode_hash(&w.challenge_one_hex, "ms_v2_bitness.challenge_one_hex")?,
        decode_hash(&w.response_zero_hex, "ms_v2_bitness.response_zero_hex")?,
        decode_hash(&w.response_one_hex, "ms_v2_bitness.response_one_hex")?,
    ))
}

fn decode_clause_wire(
    c: &MsV2ComparisonClauseWire,
) -> Result<ComparisonClauseProofV2, WireFormatError> {
    let sub: Vec<EqualitySubproofV2> = c
        .subproofs
        .iter()
        .map(|s| -> Result<EqualitySubproofV2, WireFormatError> {
            Ok(EqualitySubproofV2::from_wire(
                decode_hash(&s.announcement_hex, "comparison_subproof.announcement_hex")?,
                decode_hash(&s.response_hex, "comparison_subproof.response_hex")?,
            ))
        })
        .collect::<Result<Vec<_>, WireFormatError>>()?;
    Ok(ComparisonClauseProofV2::from_wire(
        decode_hash(
            &c.challenge_share_hex,
            "comparison_clause.challenge_share_hex",
        )?,
        sub,
    ))
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
