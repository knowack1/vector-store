/*
 * Copyright 2025-present ScyllaDB
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

use itertools::Itertools;
use std::time::{Duration, Instant};
use usearch::b1x8;

trait F32ToB1x8Iterator<'a>: Iterator<Item = &'a f32> + Sized {
    fn to_b1x8(self) -> Vec<b1x8> {
        let bytes: Vec<u8> = self
            .chunks(8)
            .into_iter()
            .map(|chunk| {
                chunk.enumerate().fold(
                    0u8,
                    |byte, (i, &val)| {
                        if val > 0.0 { byte | (1 << i) } else { byte }
                    },
                )
            })
            .collect();

        b1x8::from_u8s(&bytes).to_vec()
    }
}

impl<'a, I: Iterator<Item = &'a f32>> F32ToB1x8Iterator<'a> for I {}

fn f32_to_b1x8_1(f32_vec: &[f32]) -> Vec<b1x8> {
    f32_vec.iter().to_b1x8()
}

fn f32_to_b1x8_2(f32_vec: &[f32]) -> Vec<b1x8> {
    let bytes: Vec<u8> = f32_vec
        .chunks_exact(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(
                0u8,
                |byte, (i, &val)| {
                    if val > 0.0 { byte | (1 << i) } else { byte }
                },
            )
        })
        .collect();

    b1x8::from_u8s(&bytes).to_vec()
}

fn f32_to_b1x8_3(f32_vec: &[f32]) -> Vec<b1x8> {
    let bytes: Vec<u8> = f32_vec
        .chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(
                0u8,
                |byte, (i, &val)| {
                    if val > 0.0 { byte | (1 << i) } else { byte }
                },
            )
        })
        .collect();

    b1x8::from_u8s(&bytes).to_vec()
}

// fn f32_to_b1x8_3(data: &[f32]) -> Vec<b1x8> {
//     let bytes: Vec<u8> = data
//         .chunks_exact(8)
//         .map(|chunk| {
//             let mut byte = 0u8;
//             for (i, &val) in chunk.iter().enumerate() {
//                 if val > 0.0 {
//                     byte |= 1 << i;
//                 }
//             }
//             byte
//         })
//         .collect();

//     b1x8::from_u8s(&bytes).to_vec()
// }

fn f32_to_b1x8_4(f32_vec: &[f32]) -> Vec<b1x8> {
    let mut bytes = vec![0u8; (f32_vec.len() + 7) / 8];

    for (i, &val) in f32_vec.iter().enumerate() {
        if val > 0.0 {
            bytes[i / 8] |= 1 << i;
        }
    }

    b1x8::from_u8s(&bytes).to_vec()
}

trait SliceChunksToB1x8<'a>: Iterator<Item = &'a [f32]> + Sized {
    fn to_b1x8(self) -> Vec<b1x8> {
        let bytes: Vec<u8> = self
            .map(|chunk| {
                chunk.iter().enumerate().fold(
                    0u8,
                    |byte, (i, &val)| {
                        if val > 0.0 { byte | (1 << i) } else { byte }
                    },
                )
            })
            .collect();

        b1x8::from_u8s(&bytes).to_vec()
    }
}

impl<'a, I: Iterator<Item = &'a [f32]>> SliceChunksToB1x8<'a> for I {}

fn f32_to_b1x8_5(f32_vec: &[f32]) -> Vec<b1x8> {
    f32_vec.chunks_exact(8).to_b1x8()
}

fn benchmark_function<F>(name: &str, f: F, data: &[f32], iterations: usize) -> Duration
where
    F: Fn(&[f32]) -> Vec<b1x8>,
{
    // Warmup
    for _ in 0..10 {
        let _ = f(data);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = f(data);
    }
    let elapsed = start.elapsed();

    let avg = elapsed / iterations as u32;
    println!(
        "{:20} | Total: {:>10.3}ms | Avg: {:>8.3}μs | Throughput: {:>10.2} MB/s",
        name,
        elapsed.as_secs_f64() * 1000.0,
        avg.as_secs_f64() * 1_000_000.0,
        (data.len() * 4 * iterations) as f64 / elapsed.as_secs_f64() / 1_000_000.0
    );

    elapsed
}

fn verify_correctness(size: usize) {
    let data: Vec<f32> = (0..size)
        .map(|i| if i % 3 == 0 { 1.0 } else { -1.0 })
        .collect();

    let result1 = f32_to_b1x8_1(&data);
    let result2 = f32_to_b1x8_2(&data);
    let result3 = f32_to_b1x8_3(&data);
    let result4 = f32_to_b1x8_4(&data);
    let result5 = f32_to_b1x8_5(&data);

    assert_eq!(
        result1.len(),
        result2.len(),
        "Results have different lengths"
    );
    assert_eq!(
        result1.len(),
        result3.len(),
        "Results have different lengths"
    );
    assert_eq!(
        result1.len(),
        result4.len(),
        "Results have different lengths"
    );
    assert_eq!(
        result1.len(),
        result5.len(),
        "Results have different lengths"
    );

    // Convert to u8 for comparison
    let bytes1: &[u8] =
        unsafe { std::slice::from_raw_parts(result1.as_ptr() as *const u8, result1.len()) };
    let bytes2: &[u8] =
        unsafe { std::slice::from_raw_parts(result2.as_ptr() as *const u8, result2.len()) };
    let bytes3: &[u8] =
        unsafe { std::slice::from_raw_parts(result3.as_ptr() as *const u8, result3.len()) };
    let bytes4: &[u8] =
        unsafe { std::slice::from_raw_parts(result4.as_ptr() as *const u8, result4.len()) };
    let bytes5: &[u8] =
        unsafe { std::slice::from_raw_parts(result5.as_ptr() as *const u8, result5.len()) };

    assert_eq!(bytes1, bytes2, "Results differ between v1 and v2");
    assert_eq!(bytes1, bytes3, "Results differ between v1 and v3");
    assert_eq!(bytes1, bytes4, "Results differ between v1 and v4");
    assert_eq!(bytes1, bytes5, "Results differ between v1 and v5");

    println!("✓ Correctness verified for size {}", size);
}

fn main() {
    println!("=== F32 to B1x8 Conversion Benchmark ===\n");

    // Verify correctness first
    println!("Verifying correctness...");
    verify_correctness(1024);
    verify_correctness(1024 * 128);
    println!();

    let sizes = vec![
        ("Small (1KB)", 256),         // 256 * 4 bytes = 1KB
        ("Medium (128KB)", 32_768),   // 32KB * 4 = 128KB
        ("Large (1MB)", 262_144),     // 256KB * 4 = 1MB
        ("XLarge (16MB)", 4_194_304), // 4M * 4 = 16MB
    ];

    for (label, size) in sizes {
        println!("=== {} ({} elements, {} bytes) ===", label, size, size * 4);

        // Generate test data
        let data: Vec<f32> = (0..size)
            .map(|i| if i % 2 == 0 { 1.0 } else { -1.0 })
            .collect();

        let iterations = match size {
            s if s < 10_000 => 10_000,
            s if s < 100_000 => 1_000,
            s if s < 1_000_000 => 100,
            _ => 10,
        };

        let t1 = benchmark_function("v1: iter+chunks", f32_to_b1x8_1, &data, iterations);
        let t2 = benchmark_function("v2: chunks_exact+fold", f32_to_b1x8_2, &data, iterations);
        let t3 = benchmark_function("v3: chunks_exact+for", f32_to_b1x8_3, &data, iterations);
        let t4 = benchmark_function("v4: preallocate+index", f32_to_b1x8_4, &data, iterations);
        let t5 = benchmark_function("v5: chunks_exact+trait", f32_to_b1x8_5, &data, iterations);

        println!();

        // Calculate relative performance
        let fastest = t1.min(t2).min(t3).min(t4).min(t5);
        println!("Relative performance (vs fastest):");
        println!("  v1: {:.2}x", t1.as_secs_f64() / fastest.as_secs_f64());
        println!("  v2: {:.2}x", t2.as_secs_f64() / fastest.as_secs_f64());
        println!("  v3: {:.2}x", t3.as_secs_f64() / fastest.as_secs_f64());
        println!("  v4: {:.2}x", t4.as_secs_f64() / fastest.as_secs_f64());
        println!("  v5: {:.2}x", t5.as_secs_f64() / fastest.as_secs_f64());
        println!("\n{}\n", "=".repeat(80));
    }
}

// === F32 to B1x8 Conversion Benchmark ===

// Verifying correctness...
// ✓ Correctness verified for size 1024
// ✓ Correctness verified for size 131072

// === Small (1KB) (256 elements, 1024 bytes) ===
// v1: iter+chunks      | Total:     20.163ms | Avg:    2.016μs | Throughput:     507.86 MB/s
// v2: chunks_exact+fold | Total:      0.032ms | Avg:    0.003μs | Throughput:  321810.18 MB/s
// v3: chunks_exact+for | Total:      1.370ms | Avg:    0.136μs | Throughput:    7475.24 MB/s
// v4: preallocate+index | Total:      3.503ms | Avg:    0.350μs | Throughput:    2923.21 MB/s
// v5: chunks_exact+trait | Total:      3.248ms | Avg:    0.324μs | Throughput:    3152.61 MB/s

// Relative performance (vs fastest):
//   v1: 633.66x
//   v2: 1.00x
//   v3: 43.05x
//   v4: 110.09x
//   v5: 102.08x

// ================================================================================

// === Medium (128KB) (32768 elements, 131072 bytes) ===
// v1: iter+chunks      | Total:    193.518ms | Avg:  193.517μs | Throughput:     677.31 MB/s
// v2: chunks_exact+fold | Total:      0.003ms | Avg:    0.003μs | Throughput: 41835939.99 MB/s
// v3: chunks_exact+for | Total:     10.240ms | Avg:   10.239μs | Throughput:   12800.18 MB/s
// v4: preallocate+index | Total:     32.084ms | Avg:   32.083μs | Throughput:    4085.30 MB/s
// v5: chunks_exact+trait | Total:     25.167ms | Avg:   25.166μs | Throughput:    5208.11 MB/s

// Relative performance (vs fastest):
//   v1: 61767.50x
//   v2: 1.00x
//   v3: 3268.39x
//   v4: 10240.61x
//   v5: 8032.84x

// ================================================================================

// === Large (1MB) (262144 elements, 1048576 bytes) ===
// v1: iter+chunks      | Total:    125.194ms | Avg: 1251.939μs | Throughput:     837.56 MB/s
// v2: chunks_exact+fold | Total:      0.000ms | Avg:    0.003μs | Throughput: 312076190.48 MB/s
// v3: chunks_exact+for | Total:      6.673ms | Avg:   66.731μs | Throughput:   15713.31 MB/s
// v4: preallocate+index | Total:     24.333ms | Avg:  243.330μs | Throughput:    4309.27 MB/s
// v5: chunks_exact+trait | Total:     20.268ms | Avg:  202.678μs | Throughput:    5173.60 MB/s

// Relative performance (vs fastest):
//   v1: 372601.06x
//   v2: 1.00x
//   v3: 19860.62x
//   v4: 72419.70x
//   v5: 60320.95x

// ================================================================================

// === XLarge (16MB) (4194304 elements, 16777216 bytes) ===
// v1: iter+chunks      | Total:    200.086ms | Avg: 20008.640μs | Throughput:     838.50 MB/s
// v2: chunks_exact+fold | Total:      0.000ms | Avg:    0.011μs | Throughput: 1421797966.10 MB/s
// v3: chunks_exact+for | Total:     13.207ms | Avg: 1320.674μs | Throughput:   12703.52 MB/s
// v4: preallocate+index | Total:     42.770ms | Avg: 4277.047μs | Throughput:    3922.62 MB/s
// v5: chunks_exact+trait | Total:     42.757ms | Avg: 4275.705μs | Throughput:    3923.85 MB/s

// Relative performance (vs fastest):
//   v1: 1695647.46x
//   v2: 1.00x
//   v3: 111921.59x
//   v4: 362461.62x
//   v5: 362347.92x

// ================================================================================
