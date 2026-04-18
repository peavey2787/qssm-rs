// Accessing entropy types through zk_api must fail — they were removed.
fn main() {
    let _ = zk_api::harvest_entropy_seed();
}
