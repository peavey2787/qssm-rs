use std::collections::HashSet;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use qssm_gadget::digest_coeff_vector_from_truth_digest;

const SAMPLED_DIGESTS: usize = 10_000;
const AVALANCHE_MIN_CHANGED_COEFFS: usize = 16;

#[test]
fn sampled_digest_embeddings_are_unique() {
    let mut runner = proptest::test_runner::TestRunner::new(
        proptest::test_runner::Config::with_cases(SAMPLED_DIGESTS as u32),
    );
    let mut seen = HashSet::with_capacity(SAMPLED_DIGESTS);
    let strategy = any::<[u8; 32]>();

    for _ in 0..SAMPLED_DIGESTS {
        let digest = strategy
            .new_tree(&mut runner)
            .expect("digest strategy tree")
            .current();
        let coeffs = digest_coeff_vector_from_truth_digest(&digest);
        // Statistical evidence: sampled collisions should be negligible at this scale.
        assert!(
            seen.insert(coeffs),
            "collision found for sampled digest embedding"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn bit_flip_changes_coeff_vector_and_shows_avalanche(digest in any::<[u8; 32]>(), bit in 0usize..256usize) {
        let mut flipped = digest;
        flipped[bit / 8] ^= 1u8 << (bit % 8);

        let a = digest_coeff_vector_from_truth_digest(&digest);
        let b = digest_coeff_vector_from_truth_digest(&flipped);
        let changed = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count();

        prop_assert!(changed > 0, "bit flip must alter embedding");
        // Probabilistic guardrail: changed coefficient count should be broad, not single-limb.
        prop_assert!(
            changed >= AVALANCHE_MIN_CHANGED_COEFFS,
            "weak avalanche detected, changed coeffs={changed}"
        );
    }
}
