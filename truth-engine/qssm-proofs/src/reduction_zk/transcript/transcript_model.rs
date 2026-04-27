use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsTranscript {
    pub statement_digest: [u8; 32],
    pub result: bool,
    pub bitness_global_challenges: Vec<[u8; 32]>,
    pub comparison_global_challenge: [u8; 32],
    pub transcript_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeTranscript {
    pub commitment_coeffs: Vec<u32>,
    pub t_coeffs: Vec<u32>,
    pub z_coeffs: Vec<u32>,
    pub challenge_seed: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QssmTranscript {
    pub ms: MsTranscript,
    pub le: LeTranscript,
}

impl QssmTranscript {
    pub fn new(ms: MsTranscript, le: LeTranscript) -> Result<Self, ZkSimulationError> {
        if ms.bitness_global_challenges.is_empty() {
            return Err(ZkSimulationError::TheoremInvariant(
                "canonical transcript requires non-empty MS bitness challenge vector".to_string(),
            ));
        }
        if le.commitment_coeffs.is_empty() || le.t_coeffs.is_empty() || le.z_coeffs.is_empty() {
            return Err(ZkSimulationError::TheoremInvariant(
                "canonical transcript requires complete LE observable coordinates".to_string(),
            ));
        }
        Ok(Self { ms, le })
    }
}

impl From<&SimulatedQssmTranscript> for QssmTranscript {
    fn from(value: &SimulatedQssmTranscript) -> Self {
        Self {
            ms: MsTranscript {
                statement_digest: value.ms.statement_digest,
                result: value.ms.result,
                bitness_global_challenges: value.ms.bitness_global_challenges.clone(),
                comparison_global_challenge: value.ms.comparison_global_challenge,
                transcript_digest: value.ms.transcript_digest,
            },
            le: LeTranscript {
                commitment_coeffs: value.le.commitment_coeffs.clone(),
                t_coeffs: value.le.t_coeffs.clone(),
                z_coeffs: value.le.z_coeffs.clone(),
                challenge_seed: value.le.challenge_seed,
            },
        }
    }
}
