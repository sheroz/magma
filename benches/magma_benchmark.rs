use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use magma;

/*
fn magma_keyset_benchmark(c: &mut Criterion) {
    let mut gost = magma::CryptoEngine::new();
    let cipher_key = [0u8;32];
    c.bench_function("set_key_from_array_unsafe", |bencher| {
        bencher.iter(|| gost.set_key_from_array_unsafe(&cipher_key))
    });
    c.bench_function("set_key_from_bytes_unsafe", |bencher| {
        bencher.iter(|| gost.set_key_from_bytes_unsafe(&cipher_key))
    });
    c.bench_function("set_key_from_bytes", |bencher| {
        bencher.iter(|| gost.set_key_from_bytes(&cipher_key))
    });
}
*/

fn magma_block_benchmark(c: &mut Criterion) {
    let gost = magma::CryptoEngine::new();
    c.bench_function("encrypt", |bencher| {
        bencher.iter(|| gost.encrypt(black_box(0_u64)))
    });
    c.bench_function("decrypt", |bencher| {
        bencher.iter(|| gost.decrypt(black_box(0_u64)))
    });
}

fn magma_buffer_benchmark(c: &mut Criterion) {
    let source_buffer = [0_u8; 4096];
    let mut gost = magma::CryptoEngine::new();
    c.bench_function("encrypt", |bencher| {
        bencher.iter(|| gost.encrypt_buffer(&source_buffer, magma::Mode::ECB))
    });
    c.bench_function("decrypt", |bencher| {
        bencher.iter(|| gost.decrypt_buffer(&source_buffer, magma::Mode::ECB))
    });
}

/*
fn magma_multiple_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Magma");

    let gost = magma::CryptoEngine::new();
    for block_u64 in [u64::MIN, u32::MAX as u64, u64::MAX].iter() {
        group.bench_with_input(BenchmarkId::new("encrypt", block_u64), block_u64, |bencher, block_u64| {
            bencher.iter(|| gost.encrypt(black_box(0_u64)))
        });
        group.bench_with_input(BenchmarkId::new("decrypt", block_u64), block_u64, |bencher, block_u64| {
            bencher.iter(|| gost.encrypt(black_box(0_u64)))
        });
    }
    group.finish();
}
*/

criterion_group!(
    benches,
    // magma_keyset_benchmark,
    magma_block_benchmark,
    magma_buffer_benchmark,
    // magma_multiple_benchmark,
);

criterion_main!(benches);
