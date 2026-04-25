use std::collections::HashSet;
use std::time::Duration;
use std::thread::sleep;
use crate::render;
use crate::os::walk_heap;
use crate::os::walk_regions;
use crate::types::{HeapBlock, Region};
use crate::types::RegionKind::*;
use crate::types::RegionProtect::*;
use crate::types::RegionState::*;

pub fn scan_with_modes(mode: &String, pid: u32){

        let regions = walk_regions(pid);

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
            let used: Vec<_> = blocks.iter().filter(|b| !b.is_free).collect();
            let free: Vec<_> = blocks.iter().filter(|b| b.is_free).collect();

            let used_bytes: usize = used.iter().map(|b| b.size).sum();
            let free_bytes: usize = free.iter().map(|b| b.size).sum();

            println!("total blocks : {}", blocks.len());
            println!("used blocks  : {} ({} KB)", used.len(), used_bytes / 1024);
            println!("free blocks  : {} ({} KB)", free.len(), free_bytes / 1024);
            println!("fragmentation: {:.1}%", free_bytes as f64 / (used_bytes + free_bytes) as f64 * 100.0);
                },
        "-a"    => {
            let labels = classify(&regions);
            render::render_bar(&regions, &labels, 120);
        }
        "-v" => {
            let labels = classify(&regions);
            render::render_verbose(&regions, &labels);
        }
        _ =>{
            println!("Invalid Flag: {}", mode);
        }
    }
}

fn heap_mode(pid: u32) -> Vec<HeapBlock>{
    let heaps = walk_heap(pid);
    heaps
}

fn classify(regions: &[Region]) -> Vec<&str> {
    let mut labels = vec!["?"; regions.len()];

    // pass 1 — label stack trios
    for i in 0..regions.len() {
        if regions[i].protect == Guard {
            labels[i] = "stack-guard";

            if let Some(j) = i.checked_sub(1) {
                if regions[j].state == Reserved {
                    labels[j] = "stack-reserved";
                }
            }
            if let Some(next) = regions.get(i + 1) {
                if next.kind == Private {
                    labels[i + 1] = "stack-live";
                }
            }
        }
    }

    // pass 2 — only unlabeled private+committed regions are heap
    for i in 0..regions.len() {
        if labels[i] == "?"
            && regions[i].state == Committed
            && regions[i].kind == Private
        {
            labels[i] = "heap";
        }
    }

    // pass 3 — label remaining known types
    for i in 0..regions.len() {
        if labels[i] != "?" { continue; }
        
        labels[i] = match regions[i].kind {
            Image   => "image",
            Mapped  => "mapped",
            _       => "?",
        };
    }

    // print it
    for (i, label) in labels.iter().enumerate() {
        if *label != "?" {
            println!("{:<16} 0x{:x}", label, regions[i].base as usize);
        }
    }

    labels
}

fn diff_snapshots(
    before: &[HeapBlock],
    after:  &[HeapBlock],
) -> Vec<(usize, usize)> {
    let before_addrs: HashSet<usize> = before
        .iter()
        .filter(|b| !b.is_free)
        .map(|b| b.address)
        .collect();

    after
        .iter()
        .filter(|b| !b.is_free)
        .filter(|b| !before_addrs.contains(&(b.address as usize)))
        .map(|b| (b.address as usize, b.size))
        .collect()
}

pub fn leak_command (pid:u32, interval: u64){
    let snapshot1 = heap_mode(pid);
    let dur = Duration::new(interval, 0);
    sleep(dur);
    let snapshot2 = heap_mode(pid);
    let results = diff_snapshots(&snapshot1, &snapshot2);
    let new_bytes: usize = results.iter().map(|(_, size)| size).sum();
    println!("snapshot 1 → snapshot 2 ({}s interval)", interval);
    println!("new allocations : {}", results.len());
    println!("new bytes       : {} KB", new_bytes / 1024);
    if results.is_empty() {
        println!("no leak detected");
    } else {
        println!("\x1b[31mleak suspected — {} KB of new allocations\x1b[0m", new_bytes / 1024);
    }
}

pub fn leak_m_command (pid:u32, interval: u64, samples:u64){
    let mut prev = heap_mode(pid);
            for i in 0..samples {
                sleep(Duration::new(interval, 0));
                let next = heap_mode(pid);
                let results = diff_snapshots(&prev, &next);
                let new_bytes: usize = results.iter().map(|(_, size)| size).sum();

                print!("sample {} ", i + 1);
                println!("new allocations: {}  new bytes: {} KB  {}",
                    results.len(),
                    new_bytes / 1024,
                    if results.is_empty() { "ok" } else { "\x1b[31mleak suspected\x1b[0m" }
                );

                prev = next;
            }
}