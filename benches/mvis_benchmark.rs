use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mvis::core::scan::{diff_heap_size, diff_snapshots};
use mvis::os::MemoryProvider;
use mvis::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};
use mvis::ui::render::render_verbose_tui;
use std::process;

fn generate_heap_blocks(count: usize) -> Vec<HeapBlock> {
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        blocks.push(HeapBlock {
            address: i * 4096,
            size: 4096,
            is_free: i % 2 == 0,
            vm_protect: RegionProtect::ReadWrite,
        });
    }
    blocks
}

fn generate_regions(count: usize) -> Vec<Region> {
    let mut regions = Vec::with_capacity(count);
    for i in 0..count {
        regions.push(Region {
            base: i * 4096,
            size: 4096,
            state: RegionState::Committed,
            kind: RegionKind::Private,
            protect: RegionProtect::ReadWrite,
            name: if i % 2 == 0 {
                "[heap]".to_string()
            } else {
                "".to_string()
            },
        });
    }
    regions
}

fn bench_leak_sample(c: &mut Criterion) {
    let mut group = c.benchmark_group("leak_sample");
    group.sample_size(50);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sampling_mode(criterion::SamplingMode::Flat);
    
    for size in [1000, 10_000, 100_000].iter() {
        let before = generate_heap_blocks(*size);
        let mut after = before.clone();
        // Simulate some new allocations and freed blocks
        after.push(HeapBlock {
            address: (*size + 1) * 4096,
            size: 8192,
            is_free: false,
            vm_protect: RegionProtect::ReadWrite,
        });

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            b.iter(|| {
                let size_diff = diff_heap_size(black_box(&before), black_box(&after));
                let snapshot_diff = diff_snapshots(black_box(&before), black_box(&after));
                black_box((size_diff, snapshot_diff));
            });
        });
    }
    group.finish();
}

fn bench_tui_responsiveness(c: &mut Criterion) {
    let mut group = c.benchmark_group("tui_responsiveness");
    for size in [1000, 10_000].iter() {
        let regions = generate_regions(*size);
        let labels = vec!["heap"; *size];

        group.bench_with_input(
            BenchmarkId::new("render_verbose_tui", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    let lines = render_verbose_tui(black_box(&regions), black_box(&labels));
                    black_box(lines);
                });
            },
        );
    }
    group.finish();
}

fn bench_scan_large_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_large_process");
    group.sample_size(50);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sampling_mode(criterion::SamplingMode::Flat);
    
    let pid = process::id();

    // Note: This benchmark depends on the OS memory API and the current state of the process.
    // It is highly variable but provides a baseline for OS system call performance.
    group.bench_function("walk_regions", |b| {
        b.iter(|| {
            let regions = mvis::os::provider().walk_regions(black_box(pid));
            black_box(regions);
        });
    });

    group.bench_function("walk_heap", |b| {
        b.iter(|| {
            let heap = mvis::os::provider().walk_heap(black_box(pid));
            black_box(heap);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_leak_sample,
    bench_tui_responsiveness,
    bench_scan_large_process
);
criterion_main!(benches);
