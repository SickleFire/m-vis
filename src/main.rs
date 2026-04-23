// src/main.rs
mod render;

use std::env;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, VirtualQueryEx,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let query = &args[1];
    let pid = query.parse().unwrap();
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).expect("failed to load process") };
    let mut regions = Vec::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 { break; }
        regions.push(mbi);
        addr = addr.saturating_add(mbi.RegionSize);
        if addr == 0 { break; }
    }

    // legend
    println!(
        "\x1b[34mI\x1b[0m image  \x1b[32mM\x1b[0m mapped  \x1b[33mX\x1b[0m exec  \
         \x1b[35mH\x1b[0m heap  \x1b[36mS\x1b[0m stack  \x1b[31mG\x1b[0m guard  \x1b[90m.\x1b[0m free"
    );
    println!();
    let labels = classify(&regions);         // capture it
    render::render_bar(&regions, &labels, 120);  // pass it in
    println!();
}

fn classify(regions: &[MEMORY_BASIC_INFORMATION]) -> Vec<&str> {
    let mut labels = vec!["?"; regions.len()];

    // pass 1 — label stack trios
    for i in 0..regions.len() {
        if regions[i].Protect.contains(PAGE_GUARD) {
            labels[i] = "stack-guard";

            if let Some(j) = i.checked_sub(1) {
                if regions[j].State == MEM_RESERVE {
                    labels[j] = "stack-reserved";
                }
            }
            if let Some(next) = regions.get(i + 1) {
                if next.Type == MEM_PRIVATE {
                    labels[i + 1] = "stack-live";
                }
            }
        }
    }

    // pass 2 — only unlabeled private+committed regions are heap
    for i in 0..regions.len() {
        if labels[i] == "?"
            && regions[i].State == MEM_COMMIT
            && regions[i].Type == MEM_PRIVATE
        {
            labels[i] = "heap";
        }
    }

    // print it
    for (i, label) in labels.iter().enumerate() {
        if *label != "?" {
            println!("{:<16} 0x{:x}", label, regions[i].BaseAddress as usize);
        }
    }

    labels
}