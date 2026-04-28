use std::collections::HashSet;
use std::time::Duration;
use std::thread::sleep;
use crate::types::RegionEntry;
use crate::render;
use crate::os::walk_heap;
use crate::os::walk_regions;
use crate::types::{HeapBlock, Region};
use crate::types::RegionKind::*;
use crate::types::RegionProtect::*;
use crate::types::RegionState::*;

pub fn scan_with_modes(mode: &String, pid: u32, json: bool, output:Option<String>){

        let regions = walk_regions(pid);
        if !json {
        // legend
            println!(
            "\x1b[34mI\x1b[0m image  \x1b[32mM\x1b[0m mapped  \x1b[33mX\x1b[0m exec  \
                 \x1b[35mH\x1b[0m heap  \x1b[36mS\x1b[0m stack  \x1b[31mG\x1b[0m guard  \x1b[90m.\x1b[0m free"
            );
            println!();
        }

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
            if json {
                let labels = classify(&regions);
                let entries: Vec<RegionEntry> = regions
                    .iter()
                    .zip(labels.iter())
                    .map(|(r, l)| RegionEntry {
                        base:    r.base,
                        size:    r.size,
                        state:   r.state.clone(),
                        kind:    r.kind.clone(),
                        protect: r.protect.clone(),
                        name:    r.name.clone(),
                        label:   l.to_string(),
                    })
                    .collect();
                let json_str = serde_json::to_string_pretty(&entries).unwrap();
    
                if let Some(path) = output {
                    std::fs::write(&path, json_str).expect("failed to write file");
                    println!("saved to {}", path);
                } else {
                    println!("{}", json_str);  // default to stdout if no path given
                }
            } else{
                let labels = classify(&regions);
                render::render_bar(&regions, &labels, 120);
            }
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

        labels[i] = match regions[i].name.as_str() {
            "[stack]"        => "stack-live",
            "[heap]"         => "heap",
            "[vvar]"         => "mapped",
            "[vdso]"         => "image",
            name if name.contains(".so") => "image",
            name if !name.is_empty()     => "image",
            _                            => "?",
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

pub fn diff_heap_size(
    before: &[HeapBlock],
    after:  &[HeapBlock],
) -> usize {
    let before_total: usize = before.iter().map(|b| b.size).sum();
    let after_total:  usize = after.iter().map(|b| b.size).sum();
    if after_total > before_total {
        after_total - before_total
    } else {
        0
    }
}

pub fn leak_command(pid:u32, interval: u64){
    let snapshot1 = heap_mode(pid);
    let dur = Duration::new(interval, 0);
    sleep(dur);
    let snapshot2 = heap_mode(pid);
    
    #[cfg(target_os = "linux")]
    {
        let growth = diff_heap_size(&snapshot1, &snapshot2);
        println!("heap growth: {} KB", growth / 1024);
        if growth > 0 {
            println!("\x1b[31mleak suspected — heap grew by {} KB\x1b[0m", growth / 1024);
        } else {
            println!("no leak detected");
        }
    }

    #[cfg(target_os = "windows")]{
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