use qssm_le::{
    prove_arithmetic, verify_lattice, LeError, PublicInstance, VerifyingKey, Witness, N,
};
use qssm_utils::hashing::{hash_domain, DOMAIN_LE, DOMAIN_MS};

const DST_LE_COMMIT: [u8; 32] = *b"QSSM-LE-V1-COMMIT...............";
const DST_MS_VERIFY: [u8; 32] = *b"QSSM-MS-V1-VERIFY...............";

fn le_context() -> [u8; 32] {
    hash_domain(DOMAIN_LE, &[&DST_LE_COMMIT, b"rollup-context-a"])
}

fn ms_context() -> [u8; 32] {
    hash_domain(
        DOMAIN_MS,
        &[&DST_MS_VERIFY, b"rollup-context-b", b"replay-attempt"],
    )
}

#[test]
fn replayed_engine_a_proof_rejected_in_ms_domain_context() {
    let vk = VerifyingKey::from_seed([0x11; 32]);
    let public = PublicInstance::from_u64_nibbles(41);
    let witness = Witness::new([0i32; N]);

    let ctx_le = le_context();
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &ctx_le, [0xBB; 32]).expect("le proof");
    assert!(verify_lattice(&vk, &public, &commitment, &proof, &ctx_le).is_ok());

    let ctx_ms = ms_context();
    let replay = verify_lattice(&vk, &public, &commitment, &proof, &ctx_ms);
    assert!(
        matches!(replay, Err(LeError::DomainMismatch)),
        "expected transcript-binding rejection on domain change, got {replay:?}"
    );
}
