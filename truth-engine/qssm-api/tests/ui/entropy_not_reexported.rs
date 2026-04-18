// Accessing entropy types through qssm_api must fail — they were removed.
fn main() {
    let _ = qssm_api::harvest_entropy_seed();
}
