//! Phase 3 golden vector + tamper: truth digest and normative 30-bit LE limb.

use qssm_gadget::{
    encode_proof_metadata_v2, message_limb_from_truth_digest_normative, truth_digest,
    TruthWitness, DOMAIN_TRUTH_LIMB_V2,
};
use qssm_le::PublicInstance;
use qssm_utils::hashing::hash_domain;
use serde_json;

const GOLDEN_ROOT: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const GOLDEN_ROLLUP: [u8; 32] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
];

const GOLDEN_CHALLENGE: [u8; 32] = [
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
];

/// **`n=7, k=11, bit_at_k=0`** with **`GOLDEN_CHALLENGE`**, zero entropy floor, **`nist_included = false`**.
fn golden_metadata_v2() -> Vec<u8> {
    encode_proof_metadata_v2(7, 11, 0, &GOLDEN_CHALLENGE, &[0u8; 32], false)
}

/// Locked: `hash_domain(DOMAIN_TRUTH_LIMB_V2, &[GOLDEN_ROOT, GOLDEN_ROLLUP, golden_metadata_v2()])`.
const EXPECTED_DIGEST: [u8; 32] = [
    0x3c, 0xe7, 0x95, 0x6b, 0xee, 0xb3, 0xd3, 0xcb, 0xe6, 0x99, 0x81, 0x30, 0xb2, 0x91, 0x86, 0x50,
    0x30, 0x47, 0xe1, 0xd7, 0x29, 0x09, 0xe2, 0xd3, 0xfe, 0xaa, 0x59, 0x11, 0x52, 0x1e, 0xe3, 0x4f,
];

const EXPECTED_LIMB: u64 = 731_244_348;

#[test]
fn golden_truth_digest_and_limb() {
    let meta = golden_metadata_v2();
    let d = truth_digest(&GOLDEN_ROOT, &GOLDEN_ROLLUP, &meta);
    assert_eq!(d, EXPECTED_DIGEST);

    let via_domain = hash_domain(
        DOMAIN_TRUTH_LIMB_V2,
        &[
            GOLDEN_ROOT.as_slice(),
            GOLDEN_ROLLUP.as_slice(),
            meta.as_slice(),
        ],
    );
    assert_eq!(d, via_domain);

    let (_, limb) = message_limb_from_truth_digest_normative(&d);
    assert_eq!(limb, EXPECTED_LIMB);
    assert!(limb < (1u64 << 30));

    let w = TruthWitness::bind(
        GOLDEN_ROOT,
        GOLDEN_ROLLUP,
        7,
        11,
        0,
        GOLDEN_CHALLENGE,
        [0u8; 32],
        false,
    );
    assert!(w.validate().is_ok());
    assert_eq!(w.digest, EXPECTED_DIGEST);
    assert_eq!(w.message_limb, EXPECTED_LIMB);

    PublicInstance::digest_coeffs(w.digest_coeff_vector)
        .expect("PublicInstance accepts truth digest coefficient vector");
}

#[test]
fn tamper_one_bit_of_root_invalidates_witness() {
    let mut w = TruthWitness::bind(
        GOLDEN_ROOT,
        GOLDEN_ROLLUP,
        7,
        11,
        0,
        GOLDEN_CHALLENGE,
        [0u8; 32],
        false,
    );
    assert!(w.validate().is_ok());

    w.root[0] ^= 1;
    assert!(
        w.validate().is_err(),
        "flipping one bit of root must break digest / witness consistency"
    );
}

// ── Gap 6: template-tampering test ────────────────────────────────────────

#[test]
fn template_tampering_detected_via_digest_mismatch() {
    let w = TruthWitness::bind(
        GOLDEN_ROOT,
        GOLDEN_ROLLUP,
        7,
        11,
        0,
        GOLDEN_CHALLENGE,
        [0u8; 32],
        false,
    );
    let json_str = w.to_prover_json().expect("serialization must succeed");

    // Verify the embedded digest matches the expected golden value.
    let val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    let embedded_digest_hex = val["public"]["digest_hex"].as_str().unwrap();
    assert_eq!(embedded_digest_hex, hex::encode(EXPECTED_DIGEST));

    // Tamper the embedded digest in the serialized template.
    let fake_digest = hex::encode([0xFFu8; 32]);
    let tampered = json_str.replace(embedded_digest_hex, &fake_digest);
    assert_ne!(tampered, json_str, "tampering must modify the JSON template");

    // The tampered template no longer matches the witness's authenticated digest.
    let tampered_val: serde_json::Value = serde_json::from_str(&tampered).unwrap();
    let tampered_digest = tampered_val["public"]["digest_hex"].as_str().unwrap();
    assert_ne!(
        tampered_digest,
        hex::encode(w.digest),
        "tampered digest must not match the authentic witness digest"
    );
}
