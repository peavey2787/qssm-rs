//! Expanded adversarial coverage: proptest-driven randomised fuzzing of seam,
//! Merkle, entropy, and transcript paths.

use proptest::prelude::*;
use qssm_gadget::{
    ConstraintSystem, EngineABindingInput, EngineABindingOp, LatticePolyOp, MerklePathWitness,
    PolyOpContext, VarId, VarKind, MERKLE_DEPTH_MS,
    effective_external_entropy, xor32, TruthLimbV2Params,
    truth_digest,
};
use qssm_ms::{commit, prove, verify};
use qssm_utils::blake3_hash;

#[derive(Debug, Default)]
struct NoopCs {
    next_var: u32,
}

impl ConstraintSystem for NoopCs {
    fn allocate_variable(&mut self, _kind: VarKind) -> VarId {
        let id = VarId(self.next_var);
        self.next_var = self.next_var.saturating_add(1);
        id
    }
    fn enforce_xor(&mut self, _: VarId, _: VarId, _: VarId, _: VarId) {}
    fn enforce_full_adder(&mut self, _: VarId, _: VarId, _: VarId, _: VarId, _: VarId) {}
    fn enforce_equal(&mut self, _: VarId, _: VarId) {}
}

fn relation_digest(value: u64, target: u64, challenge: [u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(48);
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(&target.to_le_bytes());
    v.extend_from_slice(&challenge);
    blake3_hash(&v)
}

fn baseline_inputs() -> EngineABindingInput {
    let seed = [3u8; 32];
    let ledger = [4u8; 32];
    let rollup = [5u8; 32];
    let state_root = blake3_hash(b"state-root");
    let value = 100u64;
    let target = 50u64;
    let context = b"ctx".to_vec();
    let (root, salts) = commit(seed, ledger).expect("commit");
    let proof = prove(value, target, &salts, ledger, &context, &rollup).expect("prove");
    assert!(verify(root, &proof, ledger, value, target, &context, &rollup));
    let mut input = EngineABindingInput {
        state_root,
        ms_root: *root.as_bytes(),
        relation_digest: relation_digest(value, target, *proof.challenge()),
        ms_fs_v2_challenge: *proof.challenge(),
        binding_context: rollup,
        device_entropy_link: ledger,
        truth_digest: blake3_hash(b"truth-digest-adv"),
        entropy_anchor: blake3_hash(b"entropy-anchor-adv"),
        claimed_seam_commitment: [0u8; 32],
        require_ms_verified: true,
    };
    input.claimed_seam_commitment = EngineABindingOp::commitment_digest(&input);
    input
}

// ── Randomised seam field tampering ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn random_single_byte_flip_breaks_seam(field_idx in 0u8..8u8, byte_idx in 0usize..32usize) {
        let mut input = baseline_inputs();
        match field_idx {
            0 => input.state_root[byte_idx] ^= 0xFF,
            1 => input.ms_root[byte_idx] ^= 0xFF,
            2 => input.relation_digest[byte_idx] ^= 0xFF,
            3 => input.ms_fs_v2_challenge[byte_idx] ^= 0xFF,
            4 => input.binding_context[byte_idx] ^= 0xFF,
            5 => input.device_entropy_link[byte_idx] ^= 0xFF,
            6 => input.truth_digest[byte_idx] ^= 0xFF,
            _ => input.entropy_anchor[byte_idx] ^= 0xFF,
        }
        let op = EngineABindingOp;
        let mut ctx = PolyOpContext::new("adv");
        let mut cs = NoopCs::default();
        let res = op.synthesize_with_context(input, &mut cs, &mut ctx);
        prop_assert!(res.is_err(), "flipping field {field_idx} byte {byte_idx} must break seam");
    }
}

// ── Replay: same input twice yields same commitment ───────────────────────

#[test]
fn replay_produces_identical_commitment() {
    let a = baseline_inputs();
    let b = baseline_inputs();
    assert_eq!(
        EngineABindingOp::commitment_digest(&a),
        EngineABindingOp::commitment_digest(&b),
        "deterministic commitment"
    );
}

// ── Salt-forgery: wrong claimed_seam_commitment always rejected ───────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn random_commitment_forgery_rejected(noise in any::<[u8; 32]>()) {
        let mut input = baseline_inputs();
        input.claimed_seam_commitment = noise;
        // If noise accidentally equals the real commitment, skip.
        let real = EngineABindingOp::commitment_digest(&input);
        prop_assume!(noise != real);

        let op = EngineABindingOp;
        let mut ctx = PolyOpContext::new("forgery");
        let mut cs = NoopCs::default();
        let res = op.synthesize_with_context(input, &mut cs, &mut ctx);
        prop_assert!(res.is_err(), "forged commitment must be rejected");
    }
}

// ── Randomised Merkle path: bit-flip in any sibling changes root ──────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn merkle_sibling_flip_changes_root(
        sibling_idx in 0usize..MERKLE_DEPTH_MS,
        byte_idx in 0usize..32usize,
    ) {
        let leaf = [0x42u8; 32];
        let siblings: [[u8; 32]; MERKLE_DEPTH_MS] = {
            let mut s = [[0u8; 32]; MERKLE_DEPTH_MS];
            for (i, sib) in s.iter_mut().enumerate() {
                sib[0] = (i + 1) as u8;
            }
            s
        };
        let w = MerklePathWitness { leaf, siblings, leaf_index: 0 };
        let root = w.recompute_root().unwrap();

        let mut w2 = MerklePathWitness { leaf, siblings, leaf_index: 0 };
        w2.siblings[sibling_idx][byte_idx] ^= 0x01;
        let root2 = w2.recompute_root().unwrap();
        prop_assert_ne!(root, root2, "bit flip in sibling must change root");
    }
}

// ── Randomised entropy: xor32 properties ──────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn xor32_associative(a in any::<[u8; 32]>(), b in any::<[u8; 32]>(), c in any::<[u8; 32]>()) {
        prop_assert_eq!(xor32(xor32(a, b), c), xor32(a, xor32(b, c)));
    }

    #[test]
    fn effective_entropy_domain_separation(
        ext in any::<[u8; 32]>(),
        dev1 in any::<[u8; 32]>(),
        dev2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(dev1 != dev2);
        let p1 = TruthLimbV2Params {
            binding_context: [0x01u8; 32], n: 64, k: 5, bit_at_k: 1,
            challenge: [0x99u8; 32], external_entropy: ext,
            external_entropy_included: true, device_entropy_link: Some(dev1),
        };
        let p2 = TruthLimbV2Params {
            binding_context: [0x01u8; 32], n: 64, k: 5, bit_at_k: 1,
            challenge: [0x99u8; 32], external_entropy: ext,
            external_entropy_included: true, device_entropy_link: Some(dev2),
        };
        prop_assert_ne!(
            effective_external_entropy(&p1),
            effective_external_entropy(&p2),
            "different device links must produce different effective entropy"
        );
    }
}

// ── Randomised truth_digest: collision resistance spot-check ──────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn truth_digest_no_trivial_collision(
        root in any::<[u8; 32]>(),
        ctx in any::<[u8; 32]>(),
        n in 2u32..256u32,
        k in 0u32..256u32,
    ) {
        let k = k % n; // ensure k < n
        let meta1 = [n as u8, (k % 256) as u8, 0u8];
        let meta2 = [n as u8, (k % 256) as u8, 1u8];
        let d1 = truth_digest(&root, &ctx, &meta1);
        let d2 = truth_digest(&root, &ctx, &meta2);
        prop_assert_ne!(d1, d2, "different metadata must yield different digest");
    }
}
