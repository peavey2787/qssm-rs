use qssm_utils::hash_domain;

#[must_use]
pub fn domain_hash(domain: &str, inputs: &[&[u8]]) -> [u8; 32] {
    hash_domain(domain, inputs)
}
