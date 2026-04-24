// src/main.rs
mod render;

use std::env;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, VirtualQueryEx,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    let query = &args[1];
    let pid = query.parse().unwrap();
    let mode = &args[2];

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
    match mode.as_str() {
    "-h" => {
        //Heap Mode
        let blocks = heap_mode(pid);
        let used: Vec<_> = blocks.iter().filter(|(_, _, is_free)| !is_free).collect();
        let free: Vec<_> = blocks.iter().filter(|(_, _, is_free)| *is_free).collect();
    
        let used_bytes: usize = used.iter().map(|(_, size, _)| size).sum();
        let free_bytes: usize = free.iter().map(|(_, size, _)| size).sum();
    
        println!("total blocks : {}", blocks.len());
        println!("used blocks  : {} ({} KB)", used.len(), used_bytes / 1024);
        println!("free blocks  : {} ({} KB)", free.len(), free_bytes / 1024);
        println!("fragmentation: {:.1}%", free_bytes as f64 / (used_bytes + free_bytes) as f64 * 100.0);
            },
    _    => {
        let labels = classify(&regions);
        render::render_bar(&regions, &labels, 120);
    }
}
    println!();
}

fn heap_mode(pid: u32) -> Vec<(usize, usize, bool)>{
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Heap32ListFirst, Heap32ListNext,
        Heap32First, Heap32Next, HEAPLIST32, HEAPENTRY32,
        TH32CS_SNAPHEAPLIST, LF32_FREE,
    };
    let mut blocks = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid)
            .expect("failed to create snapshot");

        let mut hl = HEAPLIST32::default();
        hl.dwSize = std::mem::size_of::<HEAPLIST32>() as usize;

        // walk each heap
        if Heap32ListFirst(snapshot, &mut hl).is_ok() {
            loop {
                // walk each block in this heap
                let mut he = HEAPENTRY32::default();
                he.dwSize = std::mem::size_of::<HEAPENTRY32>() as usize;

                if Heap32First(&mut he, pid, hl.th32HeapID).is_ok() {
                    loop {
                        let is_free = he.dwFlags == LF32_FREE;
                        blocks.push((he.dwAddress as usize, he.dwBlockSize, is_free));
                        if Heap32Next(&mut he).is_err() { break; }
                    }
                }

                if Heap32ListNext(snapshot, &mut hl).is_err() { break; }
            }
        }
    }

    blocks
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