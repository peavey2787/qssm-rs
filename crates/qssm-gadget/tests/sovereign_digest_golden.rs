//! Phase 3 golden vector + tamper: sovereign digest and normative **30‑bit** LE limb.

use qssm_gadget::binding::{
    encode_proof_metadata_v1, message_limb_from_sovereign_digest_normative, sovereign_digest,
    SovereignWitness, DOMAIN_SOVEREIGN_LIMB_V1,
};
use qssm_le::PublicInstance;
use qssm_utils::hashing::hash_domain;

const GOLDEN_ROOT: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20,
];

const GOLDEN_ROLLUP: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
    0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
    0xbe, 0xbf,
];

const GOLDEN_CHALLENGE: [u8; 32] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
    0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
    0xde, 0xdf,
];

/// **`n=7, k=11, bit_at_k=0`** with **`GOLDEN_CHALLENGE`**.
fn golden_metadata() -> Vec<u8> {
    encode_proof_metadata_v1(7, 11, 0, &GOLDEN_CHALLENGE)
}

/// Locked: `hash_domain(DOMAIN_SOVEREIGN_LIMB_V1, &[GOLDEN_ROOT, GOLDEN_ROLLUP, golden_metadata()])`.
const EXPECTED_DIGEST: [u8; 32] = [
    0x9e, 0x93, 0xac, 0x6f, 0xe1, 0xb8, 0x2f, 0x30, 0xad, 0x99, 0x18, 0x9c, 0x7e, 0xaa, 0x73,
    0x43, 0x03, 0x01, 0x03, 0x16, 0xb7, 0xc3, 0x23, 0x66, 0x4f, 0xbc, 0xd3, 0x39, 0xc2, 0x88,
    0x66, 0x45,
];

const EXPECTED_LIMB: u64 = 799_839_134;

#[test]
fn golden_sovereign_digest_and_limb() {
    let meta = golden_metadata();
    let d = sovereign_digest(&GOLDEN_ROOT, &GOLDEN_ROLLUP, &meta);
    assert_eq!(d, EXPECTED_DIGEST);

    let via_domain = hash_domain(
        DOMAIN_SOVEREIGN_LIMB_V1,
        &[
            GOLDEN_ROOT.as_slice(),
            GOLDEN_ROLLUP.as_slice(),
            meta.as_slice(),
        ],
    );
    assert_eq!(d, via_domain);

    let (_, limb) = message_limb_from_sovereign_digest_normative(&d);
    assert_eq!(limb, EXPECTED_LIMB);
    assert!(limb < (1u64 << 30));

    let w = SovereignWitness::bind(GOLDEN_ROOT, GOLDEN_ROLLUP, meta);
    assert!(w.validate());
    assert_eq!(w.digest, EXPECTED_DIGEST);
    assert_eq!(w.message_limb, EXPECTED_LIMB);

    PublicInstance {
        message: w.message_limb,
    }
    .validate()
    .expect("PublicInstance accepts sovereign 30-bit limb");
}

#[test]
fn tamper_one_bit_of_root_invalidates_witness() {
    let meta = golden_metadata();
    let mut w = SovereignWitness::bind(GOLDEN_ROOT, GOLDEN_ROLLUP, meta);
    assert!(w.validate());

    w.root[0] ^= 1;
    assert!(
        !w.validate(),
        "flipping one bit of root must break digest / witness consistency"
    );
}
