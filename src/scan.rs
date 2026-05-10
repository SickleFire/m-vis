use crate::os::walk_heap;
use crate::os::walk_regions;
use crate::render;
use crate::types::RegionEntry;
use crate::types::RegionKind::*;
use crate::types::RegionProtect::*;
use crate::types::RegionState::*;
use crate::types::{HeapBlock, Region};
use rayon::prelude::*;
use std::collections::HashSet;
use std::thread::sleep;
use std::time::Duration;

/// Scans a process and displays memory information.
///
/// # Arguments
/// * `mode` - Display mode: "-a" for all, "-h" for heap, "-v" for verbose
/// * `pid` - Target process ID
/// * `json` - Whether to output JSON
/// * `output` - Optional file path for JSON output
pub fn scan_with_modes(mode: &String, pid: u32, json: bool, output: Option<String>) {
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
            let used: Vec<_> = blocks.par_iter().filter(|b| !b.is_free).collect();
            let free: Vec<_> = blocks.par_iter().filter(|b| b.is_free).collect();

            let used_bytes: usize = used.par_iter().map(|b| b.size).sum();
            let free_bytes: usize = free.par_iter().map(|b| b.size).sum();

            println!("total blocks : {}", blocks.len());
            println!("used blocks  : {} ({} KB)", used.len(), used_bytes / 1024);
            println!("free blocks  : {} ({} KB)", free.len(), free_bytes / 1024);

            let largest_free = blocks
                .iter()
                .filter(|b| b.is_free)
                .map(|b| b.size)
                .max()
                .unwrap_or(0);

            let frag = if free_bytes > 0 {
                (1.0 - (largest_free as f64 / free_bytes as f64)) * 100.0
            } else {
                0.0
            };

            println!("fragmentation: {:.1}%", frag);
            // top 10 largest allocations
            println!("\ntop 10 largest allocations:");
            let mut sorted = used.clone();
            sorted.sort_by(|a, b| b.size.cmp(&a.size));
            for block in sorted.iter().take(10) {
                println!("  0x{:x}  {} KB", block.address, block.size / 1024);
            }

            // size distribution
            println!("\nsize distribution:");
            let tiny: usize = used.iter().filter(|b| b.size < 64).count();
            let small: usize = used
                .iter()
                .filter(|b| b.size >= 64 && b.size < 1024)
                .count();
            let medium: usize = used
                .iter()
                .filter(|b| b.size >= 1024 && b.size < 65536)
                .count();
            let large: usize = used
                .iter()
                .filter(|b| b.size >= 65536 && b.size < 1024 * 1024)
                .count();
            let huge: usize = used.iter().filter(|b| b.size >= 1024 * 1024).count();

            println!("  tiny   (<64B)   : {}", tiny);
            println!("  small  (<1KB)   : {}", small);
            println!("  medium (<64KB)  : {}", medium);
            println!("  large  (<1MB)   : {}", large);
            println!("  huge   (>=1MB)  : {}", huge);

            // fragmentation assessment
            println!("\nassessment:");
            let frag = free_bytes as f64 / (used_bytes + free_bytes) as f64 * 100.0;
            if frag > 50.0 {
                println!("  \x1b[31mhigh fragmentation — consider heap compaction\x1b[0m");
            } else if frag > 25.0 {
                println!("  \x1b[33mmoderate fragmentation — monitor over time\x1b[0m");
            } else {
                println!("  \x1b[32mlow fragmentation — heap is healthy\x1b[0m");
            }

            if huge > 0 {
                println!(
                    "  \x1b[33m{} large allocations (>=1MB) detected\x1b[0m",
                    huge
                );
            }
        }
        "-a" => {
            if json {
                let labels = classify(&regions);
                let entries: Vec<RegionEntry> = regions
                    .iter()
                    .zip(labels.iter())
                    .map(|(r, l)| RegionEntry {
                        base: r.base,
                        size: r.size,
                        state: r.state.clone(),
                        kind: r.kind.clone(),
                        protect: r.protect.clone(),
                        name: r.name.clone(),
                        label: l.to_string(),
                    })
                    .collect();
                let json_str = serde_json::to_string_pretty(&entries).unwrap();

                if let Some(path) = output {
                    std::fs::write(&path, json_str).expect("failed to write file");
                    println!("saved to {}", path);
                } else {
                    println!("{}", json_str); // default to stdout if no path given
                }
            } else {
                let labels = classify(&regions);
                render::render_bar(&regions, &labels, 120);
            }
        }
        "-v" => {
            let labels = classify(&regions);
            render::render_verbose(&regions, &labels);
        }
        _ => {
            println!("Invalid Flag: {}", mode);
        }
    }
}

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

pub fn scan_with_modes_tui(
    mode: &String,
    pid: u32,
    json: bool,
    output_path: Option<&str>,
) -> Vec<Line<'static>> {
    let mut output: Vec<Line> = vec![];
    let regions = walk_regions(pid);

    if !json && !(mode != "-h" || mode != "-v") {
        output.push(Line::from(vec![
            Span::styled("I", Style::default().fg(Color::Blue)),
            Span::raw(" image  "),
            Span::styled("M", Style::default().fg(Color::Green)),
            Span::raw(" mapped  "),
            Span::styled("X", Style::default().fg(Color::Yellow)),
            Span::raw(" exec  "),
            Span::styled("H", Style::default().fg(Color::Magenta)),
            Span::raw(" heap  "),
            Span::styled("S", Style::default().fg(Color::Cyan)),
            Span::raw(" stack  "),
            Span::styled("G", Style::default().fg(Color::Red)),
            Span::raw(" guard  "),
            Span::styled(".", Style::default().fg(Color::DarkGray)),
            Span::raw(" free"),
        ]));
    }

    match mode.as_str() {
        "-h" => {
            let blocks = heap_mode(pid);
            let used: Vec<_> = blocks.par_iter().filter(|b| !b.is_free).collect();
            let free: Vec<_> = blocks.par_iter().filter(|b| b.is_free).collect();
            let used_bytes: usize = used.par_iter().map(|b| b.size).sum();
            let free_bytes: usize = free.par_iter().map(|b| b.size).sum();

            let largest_free = blocks
                .iter()
                .filter(|b| b.is_free)
                .map(|b| b.size)
                .max()
                .unwrap_or(0);

            let frag = if free_bytes > 0 {
                (1.0 - (largest_free as f64 / free_bytes as f64)) * 100.0
            } else {
                0.0
            };

            output.push(Line::raw(format!("total blocks : {}", blocks.len())));
            output.push(Line::raw(format!(
                "used blocks  : {} ({} KB)",
                used.len(),
                used_bytes / 1024
            )));
            output.push(Line::raw(format!(
                "free blocks  : {} ({} KB)",
                free.len(),
                free_bytes / 1024
            )));
            output.push(Line::raw(format!("fragmentation: {:.1}%", frag)));
            output.push(Line::raw("top 10 largest allocations:"));
            let mut sorted = used.clone();
            sorted.sort_by(|a, b| b.size.cmp(&a.size));
            for block in sorted.iter().take(10) {
                output.push(Line::raw(format!(
                    "  0x{:x}  {} KB",
                    block.address,
                    block.size / 1024
                )));
            }
            output.push(Line::raw("size distribution:"));
            let tiny = used.iter().filter(|b| b.size < 64).count();
            let small = used
                .iter()
                .filter(|b| b.size >= 64 && b.size < 1024)
                .count();
            let medium = used
                .iter()
                .filter(|b| b.size >= 1024 && b.size < 65536)
                .count();
            let large = used
                .iter()
                .filter(|b| b.size >= 65536 && b.size < 1024 * 1024)
                .count();
            let huge = used.iter().filter(|b| b.size >= 1024 * 1024).count();
            output.push(Line::raw(format!("  tiny   (<64B)   : {}", tiny)));
            output.push(Line::raw(format!("  small  (<1KB)   : {}", small)));
            output.push(Line::raw(format!("  medium (<64KB)  : {}", medium)));
            output.push(Line::raw(format!("  large  (<1MB)   : {}", large)));
            output.push(Line::raw(format!("  huge   (>=1MB)  : {}", huge)));
            output.push(Line::raw("assessment:"));
            let frag = free_bytes as f64 / (used_bytes + free_bytes) as f64 * 100.0;
            if frag > 50.0 {
                output.push(Line::from(Span::styled(
                    "  high fragmentation — consider heap compaction",
                    Style::default().fg(Color::Red),
                )));
            } else if frag > 25.0 {
                output.push(Line::from(Span::styled(
                    "  moderate fragmentation — monitor over time",
                    Style::default().fg(Color::Yellow),
                )));
            } else {
                output.push(Line::from(Span::styled(
                    "  low fragmentation — heap is healthy",
                    Style::default().fg(Color::Green),
                )));
            }
            if huge > 0 {
                output.push(Line::from(Span::styled(
                    format!("  {} large allocations (>=1MB) detected", huge),
                    Style::default().fg(Color::Yellow),
                )));
            }
            output
        }
        "-a" => {
            if json {
                let labels = classify(&regions);
                let entries: Vec<RegionEntry> = regions
                    .iter()
                    .zip(labels.iter())
                    .map(|(r, l)| RegionEntry {
                        base: r.base,
                        size: r.size,
                        state: r.state.clone(),
                        kind: r.kind.clone(),
                        protect: r.protect.clone(),
                        name: r.name.clone(),
                        label: l.to_string(),
                    })
                    .collect();
                let json_str = serde_json::to_string_pretty(&entries).unwrap();
                if let Some(path) = output_path {
                    std::fs::write(path, &json_str).expect("failed to write file");
                    output.push(Line::raw(format!("saved to {}", path)));
                } else {
                    for line in json_str.lines() {
                        output.push(Line::raw(line.to_string()));
                    }
                }
                output
            } else {
                let labels = classify(&regions);
                output.push(render::render_bar_tui(&regions, &labels, 120));
                output
            }
        }
        "-v" => {
            let labels = classify(&regions);
            output.extend(render::render_verbose_tui(&regions, &labels));
            output
        }
        _ => {
            output.push(Line::raw(format!("Invalid Flag: {}", mode)));
            output
        }
    }
}

fn heap_mode(pid: u32) -> Vec<HeapBlock> {
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
        if labels[i] == "?" && regions[i].state == Committed && regions[i].kind == Private {
            labels[i] = "heap";
        }
    }

    // pass 3 — label remaining known types
    for i in 0..regions.len() {
        if labels[i] != "?" {
            continue;
        }

        labels[i] = match regions[i].kind {
            Image => "image",
            Mapped => "mapped",
            _ => "?",
        };

        labels[i] = match regions[i].name.as_str() {
            "[stack]" => "stack-live",
            "[heap]" => "heap",
            "[vvar]" => "mapped",
            "[vdso]" => "image",
            name if name.contains(".so") => "image",
            name if !name.is_empty() => "image",
            _ => match regions[i].kind {
                Image => "image",
                Mapped => "mapped",
                _ => "?",
            },
        };
    }

    // Deprecated
    /*for (i, label) in labels.iter().enumerate() {
        if *label != "?" {
            println!("{:<16} 0x{:x}", label, regions[i].base as usize);
        }
    }*/

    labels
}

fn diff_snapshots(before: &[HeapBlock], after: &[HeapBlock]) -> Vec<(usize, usize)> {
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

pub fn diff_heap_size(before: &[HeapBlock], after: &[HeapBlock]) -> usize {
    let before_total: usize = before.iter().map(|b| b.size).sum();
    let after_total: usize = after.iter().map(|b| b.size).sum();
    if after_total > before_total {
        after_total - before_total
    } else {
        0
    }
}

pub fn leak_command(pid: u32, interval: u64) {
    let snapshot1 = heap_mode(pid);
    let dur = Duration::new(interval, 0);
    #[cfg(target_os = "linux")]
    let regions = walk_regions(pid);

    #[cfg(target_os = "linux")]
    let trace = {
        match crate::stack_trace::StackTrace::capture(pid, &regions) {
            Ok(t) => {
                eprintln!("[dbg] stack captured: {} frames", t.frames.len());
                Ok(t)
            }
            Err(e) => {
                eprintln!("[dbg] stack capture failed: {}", e);
                Err(e)
            }
        }
    };
    sleep(dur);
    let snapshot2 = heap_mode(pid);

    #[cfg(target_os = "linux")]
    {
        let growth = diff_heap_size(&snapshot1, &snapshot2);
        println!("heap growth: {} KB", growth / 1024);
        if growth > 0 {
            println!(
                "\x1b[31mleak suspected — heap grew by {} KB\x1b[0m",
                growth / 1024
            );

            if let Ok(t) = trace {
                println!("\ncall stack at time of snapshot:");
                for (i, frame) in t.frames.iter().enumerate() {
                    println!("  #{:<2} {}", i, frame.symbol);
                }
            }
        } else {
            println!("no leak detected");
        }
    }

    #[cfg(target_os = "windows")]
    {
        let results = diff_snapshots(&snapshot1, &snapshot2);
        let new_bytes: usize = results.iter().map(|(_, size)| size).sum();
        println!("snapshot 1 → snapshot 2 ({}s interval)", interval);
        println!("new allocations : {}", results.len());
        println!("new bytes       : {} KB", new_bytes / 1024);
        if results.is_empty() {
            println!("no leak detected");
        } else {
            println!(
                "\x1b[31mleak suspected — {} KB of new allocations\x1b[0m",
                new_bytes / 1024
            );
        }
    }
}

pub fn leak_command_tui(pid: u32, interval: u64) -> Vec<Line<'static>> {
    let mut output: Vec<Line> = vec![];
    let snapshot1 = heap_mode(pid);
    let dur = Duration::new(interval, 0);
    #[cfg(target_os = "linux")]
    let regions = walk_regions(pid);

    #[cfg(target_os = "linux")]
    let trace = {
        match crate::stack_trace::StackTrace::capture(pid, &regions) {
            Ok(t) => {
                output.push(Line::raw(format!(
                    "[dbg] stack captured: {} frames",
                    t.frames.len()
                )));
                Ok(t)
            }
            Err(e) => {
                output.push(Line::raw(format!("[dbg] stack capture failed: {}", e)));
                Err(e)
            }
        }
    };
    sleep(dur);
    let snapshot2 = heap_mode(pid);

    #[cfg(target_os = "linux")]
    {
        let growth = diff_heap_size(&snapshot1, &snapshot2);
        output.push(Line::raw(format!("heap growth: {} KB", growth / 1024)));
        if growth > 0 {
            output.push(Line::from(Span::styled(
                format!("leak suspected — heap grew by {} KB", growth / 1024),
                Style::default().fg(Color::Red),
            )));

            if let Ok(t) = trace {
                output.push(Line::from(Span::styled(
                    "call stack at time of snapshot:",
                    Style::default().fg(Color::Cyan),
                )));
                for (i, frame) in t.frames.iter().enumerate() {
                    output.push(Line::raw(format!("  #{:<2} {}", i, frame.symbol)));
                }
            }
        } else {
            output.push(Line::raw(format!("no leak detected")));
        }
        output
    }

    #[cfg(target_os = "windows")]
    {
        let results = diff_snapshots(&snapshot1, &snapshot2);
        let new_bytes: usize = results.iter().map(|(_, size)| size).sum();
        output.push(Line::raw(format!(
            "snapshot 1 → snapshot 2 ({}s interval)",
            interval
        )));
        output.push(Line::raw(format!("new allocations : {}", results.len())));
        output.push(Line::raw(format!(
            "new bytes       : {} KB",
            new_bytes / 1024
        )));
        if results.is_empty() {
            output.push(Line::from(vec![Span::styled(
                "no leak detected",
                Style::default().fg(Color::Green),
            )]));
            output
        } else {
            output.push(Line::from(vec![Span::styled(
                format!(
                    "leak suspected — {} KB of new allocations",
                    new_bytes / 1024
                ),
                Style::default().fg(Color::Red),
            )]));
            output
        }
    }
}

pub fn leak_m_command(pid: u32, interval: u64, samples: u64) {
    let mut prev = heap_mode(pid);
    for i in 0..samples {
        sleep(Duration::new(interval, 0));
        let next = heap_mode(pid);
        let results = diff_snapshots(&prev, &next);
        let new_bytes: usize = results.iter().map(|(_, size)| size).sum();

        print!("sample {} ", i + 1);
        println!(
            "new allocations: {}  new bytes: {} KB  {}",
            results.len(),
            new_bytes / 1024,
            if results.is_empty() {
                "ok"
            } else {
                "\x1b[31mleak suspected\x1b[0m"
            }
        );

        prev = next;
    }
}

use std::sync::mpsc::Sender;

pub fn leak_m_command_tui(pid: u32, interval: u64, samples: u64, tx: Sender<Line<'static>>) {
    let mut prev = heap_mode(pid);

    for i in 0..samples {
        tx.send(Line::raw(format!("waiting {}s...", interval))).ok();
        sleep(Duration::new(interval, 0));

        let next = heap_mode(pid);
        let results = diff_snapshots(&prev, &next);
        let new_bytes: usize = results.iter().map(|(_, size)| size).sum();

        tx.send(Line::raw(format!("sample {}/{}", i + 1, samples)))
            .ok();

        let status_span = if results.is_empty() {
            Span::styled("ok", Style::default().fg(Color::Green))
        } else {
            Span::styled("leak suspected", Style::default().fg(Color::Red))
        };

        tx.send(Line::from(vec![
            Span::raw(format!(
                "  new allocations: {}  new bytes: {} KB  ",
                results.len(),
                new_bytes / 1024,
            )),
            status_span,
        ]))
        .ok();

        prev = next;
    }

    tx.send(Line::raw("leak-m complete")).ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HeapBlock, Region, RegionKind, RegionProtect, RegionState};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_block(address: usize, size: usize, is_free: bool) -> HeapBlock {
        HeapBlock {
            address,
            size,
            is_free,
        }
    }

    fn make_region(
        base: usize,
        size: usize,
        state: RegionState,
        kind: RegionKind,
        protect: RegionProtect,
        name: &str,
    ) -> Region {
        Region {
            base,
            size,
            state,
            kind,
            protect,
            name: name.to_string(),
        }
    }

    // ── diff_heap_size ────────────────────────────────────────────────────────

    #[test]
    fn heap_growth_detected() {
        let before = vec![make_block(0x1000, 4096, false)];
        let after = vec![
            make_block(0x1000, 4096, false),
            make_block(0x2000, 2048, false),
        ];
        assert_eq!(diff_heap_size(&before, &after), 2048);
    }

    #[test]
    fn no_growth_when_equal() {
        let snap = vec![make_block(0x1000, 4096, false)];
        assert_eq!(diff_heap_size(&snap, &snap), 0);
    }

    #[test]
    fn no_growth_when_shrinks() {
        let before = vec![make_block(0x1000, 8192, false)];
        let after = vec![make_block(0x1000, 4096, false)];
        // shrinkage returns 0, not a wrapping negative
        assert_eq!(diff_heap_size(&before, &after), 0);
    }

    #[test]
    fn growth_counts_free_blocks_too() {
        // diff_heap_size sums ALL blocks regardless of is_free
        let before = vec![make_block(0x1000, 1024, false)];
        let after = vec![
            make_block(0x1000, 1024, false),
            make_block(0x2000, 512, true),
        ];
        assert_eq!(diff_heap_size(&before, &after), 512);
    }

    // ── diff_snapshots ────────────────────────────────────────────────────────

    #[test]
    fn new_allocs_detected() {
        let before = vec![make_block(0x1000, 64, false)];
        let after = vec![
            make_block(0x1000, 64, false),
            make_block(0x2000, 128, false), // new
        ];
        let results = diff_snapshots(&before, &after);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (0x2000, 128));
    }

    #[test]
    fn no_false_positives_on_same_snapshot() {
        let snap = vec![
            make_block(0x1000, 64, false),
            make_block(0x2000, 128, false),
        ];
        assert!(diff_snapshots(&snap, &snap).is_empty());
    }

    #[test]
    fn free_blocks_excluded_from_diff() {
        let before = vec![];
        // a new block that is free should NOT appear in leak diff
        let after = vec![make_block(0x3000, 256, true)];
        assert!(diff_snapshots(&before, &after).is_empty());
    }

    #[test]
    fn multiple_new_allocs_all_reported() {
        let before = vec![];
        let after = vec![
            make_block(0x1000, 64, false),
            make_block(0x2000, 128, false),
            make_block(0x3000, 32, false),
        ];
        let results = diff_snapshots(&before, &after);
        assert_eq!(results.len(), 3);
        let total: usize = results.iter().map(|(_, s)| s).sum();
        assert_eq!(total, 64 + 128 + 32);
    }

    // ── classify ──────────────────────────────────────────────────────────────
    // classify is private; these tests live in the same module so they can see it.

    #[test]
    fn stack_trio_labeled_correctly() {
        let regions = vec![
            make_region(0x7ff0_0000, 4096, Reserved, Private, ReadWrite, ""), // stack-reserved
            make_region(0x7ff1_0000, 4096, Committed, Private, Guard, ""), // stack-guard  (pass 1 trigger)
            make_region(0x7ff2_0000, 65536, Committed, Private, ReadWrite, ""), // stack-live
        ];
        let labels = classify(&regions);
        assert_eq!(labels[0], "stack-reserved");
        assert_eq!(labels[1], "stack-guard");
        assert_eq!(labels[2], "stack-live");
    }

    #[test]
    fn heap_fallback_for_private_committed() {
        let regions = vec![make_region(
            0x0030_0000,
            8192,
            Committed,
            Private,
            ReadWrite,
            "",
        )];
        let labels = classify(&regions);
        assert_eq!(labels[0], "heap");
    }

    #[test]
    fn named_heap_region_labeled_heap() {
        let regions = vec![make_region(
            0x0040_0000,
            4096,
            Committed,
            Private,
            ReadWrite,
            "[heap]",
        )];
        let labels = classify(&regions);
        assert_eq!(labels[0], "heap");
    }

    #[test]
    fn so_file_labeled_image() {
        let regions = vec![make_region(
            0x7f00_0000,
            4096,
            Committed,
            Image,
            Execute,
            "/usr/lib/libc.so.6",
        )];
        let labels = classify(&regions);
        assert_eq!(labels[0], "image");
    }

    #[test]
    fn mapped_kind_labeled_mapped() {
        let regions = vec![make_region(
            0x0010_0000,
            4096,
            Committed,
            Mapped,
            Readonly,
            "",
        )];
        let labels = classify(&regions);
        assert_eq!(labels[0], "mapped");
    }

    #[test]
    fn classify_output_length_matches_input() {
        let regions = vec![
            make_region(0x1000, 4096, Committed, Private, ReadWrite, ""),
            make_region(0x2000, 4096, Committed, Mapped, Readonly, ""),
            make_region(0x3000, 4096, Reserved, Private, NoAccess, ""),
        ];
        let labels = classify(&regions);
        assert_eq!(labels.len(), regions.len());
    }

    // ── scan_with_modes (smoke test — uses live process) ─────────────────────

    #[test]
    fn scan_all_mode_does_not_panic() {
        let pid = std::process::id();
        // just make sure it runs without panicking; we don't validate output
        scan_with_modes(&"-a".to_string(), pid, false, None);
    }

    #[test]
    fn scan_verbose_mode_does_not_panic() {
        let pid = std::process::id();
        scan_with_modes(&"-v".to_string(), pid, false, None);
    }

    #[test]
    fn scan_invalid_mode_does_not_panic() {
        let pid = std::process::id();
        scan_with_modes(&"-z".to_string(), pid, false, None);
    }

    #[test]
    fn scan_json_to_stdout_does_not_panic() {
        let pid = std::process::id();
        scan_with_modes(&"-a".to_string(), pid, true, None);
    }
}
