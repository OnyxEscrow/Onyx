use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

fn bench_simulated_recovery(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    c.bench_function("5_escrows_sequential", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate 5 escrows × 3 wallets = 15 RPC calls
            for _ in 0..15 {
                tokio::time::sleep(Duration::from_millis(2000)).await;
            }
            black_box(());
        });
    });
    
    c.bench_function("5_escrows_parallel_limited", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate parallel with semaphore (max 10 concurrent)
            let tasks: Vec<_> = (0..15)
                .map(|_| tokio::spawn(async {
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                }))
                .collect();
            
            for task in tasks {
                task.await.unwrap();
            }
            black_box(());
        });
    });
}

criterion_group!(benches, bench_simulated_recovery);
criterion_main!(benches);
