use std::collections::BTreeMap;

use qssm_utils::hashing::hash_domain;

const DAG_NODE_DOMAIN: &str = "MSSQ-CAUSAL-DAG-NODE-v1.0";
const DAG_TIP_MIX_DOMAIN: &str = "MSSQ-LATTICE-TIP-MIX-v1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyPulse {
    pub pulse_hash: [u8; 32],
    pub tip_refs: Vec<[u8; 32]>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Default, Clone)]
pub struct CausalDag {
    nodes: BTreeMap<[u8; 32], EntropyPulse>,
    tips: Vec<[u8; 32]>,
}

impl CausalDag {
    #[must_use]
    pub fn tip_count(&self) -> usize {
        self.tips.len()
    }

    #[must_use]
    pub fn current_tips(&self) -> Vec<[u8; 32]> {
        self.tips.clone()
    }

    pub fn add_pulse(
        &mut self,
        body_hash: [u8; 32],
        timestamp_secs: u64,
        requested_refs: usize,
    ) -> Result<EntropyPulse, String> {
        let refs = requested_refs.clamp(2, 3);
        let selected = self.tips.iter().take(refs).copied().collect::<Vec<_>>();
        if self.tips.len() >= 2 && selected.len() < 2 {
            return Err("causal DAG requires referencing 2-3 previous tips".into());
        }
        let pulse_hash = hash_domain(
            DAG_NODE_DOMAIN,
            &[
                body_hash.as_slice(),
                &timestamp_secs.to_le_bytes(),
                &selected.concat(),
            ],
        );
        let pulse = EntropyPulse {
            pulse_hash,
            tip_refs: selected.clone(),
            timestamp_secs,
        };
        self.nodes.insert(pulse_hash, pulse.clone());
        self.tips.retain(|h| !selected.contains(h));
        self.tips.insert(0, pulse_hash);
        while self.tips.len() > 64 {
            let _ = self.tips.pop();
        }
        Ok(pulse)
    }
}

#[must_use]
pub fn lattice_anchor_seed_with_tips(base_seed: [u8; 32], tip_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = tip_hashes.to_vec();
    sorted.sort_unstable();
    hash_domain(
        DAG_TIP_MIX_DOMAIN,
        &[base_seed.as_slice(), &sorted.concat()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_references_prior_tips() {
        let mut dag = CausalDag::default();
        let p0 = dag.add_pulse([1u8; 32], 1, 2).expect("genesis");
        let p1 = dag.add_pulse([2u8; 32], 2, 2).expect("second");
        let p2 = dag.add_pulse([3u8; 32], 3, 3).expect("third");
        assert_eq!(p0.tip_refs.len(), 0);
        assert!((1..=2).contains(&p1.tip_refs.len()));
        assert!((1..=3).contains(&p2.tip_refs.len()));
    }

    #[test]
    fn tip_mix_changes_seed() {
        let seed = [7u8; 32];
        let mixed_a = lattice_anchor_seed_with_tips(seed, &[[1u8; 32], [2u8; 32]]);
        let mixed_b = lattice_anchor_seed_with_tips(seed, &[[1u8; 32], [3u8; 32]]);
        assert_ne!(mixed_a, mixed_b);
    }
}
