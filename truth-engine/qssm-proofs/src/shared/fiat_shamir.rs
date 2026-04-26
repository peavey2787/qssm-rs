use crate::shared::hash_utils::domain_hash;
use qssm_le::{
    encode_rq_coeffs_le, Commitment, PublicInstance, RqPoly, VerifyingKey, C_POLY_SIZE, C_POLY_SPAN,
};

pub struct FiatShamirOracle;

impl FiatShamirOracle {
    #[must_use]
    pub fn ms_bitness_challenge(
        domain_ms: &str,
        root: &[u8; 32],
        n: u8,
        k: u8,
        binding_entropy: &[u8; 32],
        value: u64,
        target: u64,
        context: &[u8],
        binding_context: &[u8; 32],
    ) -> [u8; 32] {
        domain_hash(
            domain_ms,
            &[
                b"fs_v2",
                root.as_slice(),
                &[n],
                &[k],
                binding_entropy.as_slice(),
                &value.to_le_bytes(),
                &target.to_le_bytes(),
                context,
                binding_context.as_slice(),
            ],
        )
    }

    #[must_use]
    pub fn ms_comparison_challenge(
        domain_ms: &str,
        statement_digest: &[u8; 32],
        clause_announcements: &[u8],
    ) -> [u8; 32] {
        domain_hash(
            domain_ms,
            &[b"ms_comparison_challenge", statement_digest.as_slice(), clause_announcements],
        )
    }

    #[must_use]
    pub fn le_challenge_seed(
        domain_sim: &str,
        label: &[u8],
        simulator_seed: Option<&[u8; 32]>,
        binding_context: &[u8; 32],
        vk: &VerifyingKey,
        public_fs_bytes: &[u8],
        commitment: &Commitment,
    ) -> [u8; 32] {
        match simulator_seed {
            Some(seed) => domain_hash(
                domain_sim,
                &[
                    label,
                    seed.as_slice(),
                    binding_context.as_slice(),
                    &vk.crs_seed,
                    public_fs_bytes,
                    &encode_rq_coeffs_le(&commitment.0),
                ],
            ),
            None => domain_hash(
                domain_sim,
                &[
                    label,
                    binding_context.as_slice(),
                    &vk.crs_seed,
                    public_fs_bytes,
                    &encode_rq_coeffs_le(&commitment.0),
                ],
            ),
        }
    }

    #[must_use]
    pub fn le_challenge_poly(seed: &[u8; 32]) -> [i32; C_POLY_SIZE] {
        let mut coeffs = [0i32; C_POLY_SIZE];
        let span = C_POLY_SPAN as u32;
        let mut filled = 0usize;
        let mut ctr = 0u32;
        while filled < C_POLY_SIZE {
            let h = domain_hash("QSSM-LE-CHALLENGE-POLY-v1.0", &[seed, &ctr.to_le_bytes()]);
            for chunk in h.as_slice().chunks_exact(4) {
                if filled >= C_POLY_SIZE {
                    break;
                }
                let raw = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                coeffs[filled] = (raw % (2 * span + 1)) as i32 - C_POLY_SPAN;
                filled += 1;
            }
            ctr = ctr.wrapping_add(1);
        }
        coeffs
    }

    #[must_use]
    pub fn le_programmed_query_digest(
        domain_sim: &str,
        binding_context: &[u8; 32],
        vk: &VerifyingKey,
        public: &PublicInstance,
        commitment: &Commitment,
        t: &RqPoly,
        public_fs_bytes: &[u8],
    ) -> [u8; 32] {
        let _ = public;
        domain_hash(
            domain_sim,
            &[
                b"le_programmed_query_digest",
                binding_context.as_slice(),
                &vk.crs_seed,
                public_fs_bytes,
                &encode_rq_coeffs_le(&commitment.0),
                &encode_rq_coeffs_le(t),
            ],
        )
    }
}
