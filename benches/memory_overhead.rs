use mvis::types::{HeapBlock, RegionProtect};
use sysinfo::System;

fn main() {
    let mut sys = System::new_all();
    let pid = sysinfo::get_current_pid().unwrap();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mem_before = sys.process(pid).unwrap().memory();

    // Generate 100k heap blocks to simulate memory overhead of mvis itself when scanning a large process
    let mut blocks = Vec::with_capacity(100_000);
    for i in 0..100_000 {
        blocks.push(HeapBlock {
            address: i * 4096,
            size: 4096,
            is_free: i % 2 == 0,
            vm_protect: RegionProtect::ReadWrite,
        });
    }

    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mem_after = sys.process(pid).unwrap().memory();

    // Prevent compiler from optimizing away the vector
    std::hint::black_box(&blocks);

    let diff = mem_after.saturating_sub(mem_before);

    println!("Generated {} simulated heap blocks.", blocks.len());
    println!(
        "mvis memory overhead: {:.2} MB",
        diff as f64 / 1024.0 / 1024.0
    );
}
