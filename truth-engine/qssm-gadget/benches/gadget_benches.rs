use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qssm_gadget::{digest_coeff_vector_from_truth_digest, truth_digest};

fn bench_truth_digest(c: &mut Criterion) {
    let root = [0xABu8; 32];
    let ctx = [0xCDu8; 32];
    let meta = [64u8, 5, 1];
    c.bench_function("truth_digest", |b| {
        b.iter(|| truth_digest(black_box(&root), black_box(&ctx), black_box(&meta)))
    });
}

fn bench_digest_coeff_vector(c: &mut Criterion) {
    let digest = [0x42u8; 32];
    c.bench_function("digest_coeff_vector", |b| {
        b.iter(|| digest_coeff_vector_from_truth_digest(black_box(&digest)))
    });
}

criterion_group!(benches, bench_truth_digest, bench_digest_coeff_vector);
criterion_main!(benches);
