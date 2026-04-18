#![no_main]

use libfuzzer_sys::fuzz_target;
use qssm_le::{
    verify_lattice, Commitment, LatticeProof, PublicInstance, RqPoly, VerifyingKey, C_POLY_SIZE, N,
    PUBLIC_DIGEST_COEFFS,
};

const U32_BYTES: usize = 4;
const POLY_BYTES: usize = N * U32_BYTES;
const DIGEST_COEFF_BYTES: usize = PUBLIC_DIGEST_COEFFS * U32_BYTES;
const FIXED_SIZE: usize = 32 + DIGEST_COEFF_BYTES + POLY_BYTES * 3 + 32 + 32;

fn read_u32_le(input: &[u8], offset: &mut usize) -> u32 {
    let i = *offset;
    *offset += 4;
    u32::from_le_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]])
}

fn read_poly(input: &[u8], offset: &mut usize) -> RqPoly {
    let mut coeffs = [0u32; N];
    for coeff in &mut coeffs {
        *coeff = read_u32_le(input, offset);
    }
    RqPoly(coeffs)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < FIXED_SIZE {
        return;
    }
    let mut o = 0usize;

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[o..o + 32]);
    o += 32;
    let vk = VerifyingKey::from_seed(seed);

    let mut digest_coeffs = [0u32; PUBLIC_DIGEST_COEFFS];
    for c in &mut digest_coeffs {
        *c = read_u32_le(data, &mut o) & 0x0f;
    }
    let public = match PublicInstance::digest_coeffs(digest_coeffs) {
        Ok(p) => p,
        Err(_) => return,
    };

    let commitment = Commitment(read_poly(data, &mut o));
    let t = read_poly(data, &mut o);
    let z = read_poly(data, &mut o);

    let mut challenge_seed = [0u8; 32];
    challenge_seed.copy_from_slice(&data[o..o + 32]);
    o += 32;

    let mut context = [0u8; 32];
    context.copy_from_slice(&data[o..o + 32]);

    let proof = LatticeProof {
        t,
        z,
        challenge_seed,
    };

    let _ = C_POLY_SIZE; // ensure challenge config remains linked in fuzz build
    let _ = verify_lattice(&vk, &public, &commitment, &proof, &context);
});
