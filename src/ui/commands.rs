use crate::core::delta::LeakDelta;
use crate::core::scan::leak_command_tui;
use crate::core::scan::scan_with_modes_tui;
use crate::os;
use crate::os::MemoryProvider;
use crate::types::HeapBlock;
use crate::utils::formatting::format_bytes;
use ratatui::text::Line;

pub struct ScanResult {
    pub lines: Vec<Line<'static>>,
    pub pid: u32,
    pub memory_mb: u64,
    // heap data — only populated when mode is "-h"
    pub blocks: Vec<HeapBlock>,
    pub used_bytes: usize,
    pub free_bytes: usize,
    pub frag: f64,
    pub pointer_blocks: std::collections::HashSet<usize>,
    pub referenced_blocks: std::collections::HashSet<usize>,
}

use std::sync::mpsc::Sender;

/// Returns `true` if `name` matches a Rayon worker thread naming convention.
pub fn is_worker_thread_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "rayon-worker" || name.starts_with("rayon-worker-")
}

/// Returns `true` if a process with the given `name` should be shown in listings.
///
/// Worker threads are always hidden; if `filter` is `Some`, the name must also contain the filter string.
pub fn process_name_is_visible(name: &str, filter: Option<&str>) -> bool {
    if is_worker_thread_name(name) {
        return false;
    }

    filter.is_none_or(|f| name.to_ascii_lowercase().contains(f))
}

/// Returns `true` if a sysinfo [`Process`](sysinfo::Process) entry should appear in listings.
///
/// Kernel threads are always hidden; the process name is further checked with [`process_name_is_visible`].
pub fn process_is_visible(process: &sysinfo::Process, filter: Option<&str>) -> bool {
    if process.thread_kind().is_some() {
        return false;
    }

    let name = process.name().to_string_lossy();
    process_name_is_visible(name.as_ref(), filter)
}

/// Runs a multi-sample heap leak detection scan for the process in `args[1]`.
///
/// `args[2]` is the interval in seconds between samples and `args[3]` is the sample count.
/// Each result line is sent to `tx` as it is produced.
pub fn leak_m(args: Vec<&str>, tx: Sender<Line<'static>>) -> Result<(), String> {
    let queryp = args[1];
    let pid = find_pid(queryp.to_string())?;
    let interval: u64 = args[2].parse().unwrap();
    let samples: u64 = args[3].parse().unwrap();
    crate::core::scan::leak_m_command_tui(pid, interval, samples, tx);
    Ok(())
}

/// Performs a single-interval heap leak detection scan for the process in `args[1]`.
///
/// `args[2]` is the wait interval in seconds between the two snapshots.
/// Returns styled output lines and a [`LeakDelta`] describing the growth.
pub fn leak(args: Vec<&str>) -> Result<(Vec<Line<'static>>, LeakDelta), String> {
    let queryp = args[1];
    let pid = find_pid(queryp.to_string()).unwrap();
    let interval: u64 = args[2].parse().unwrap();
    let (lines, delta) = leak_command_tui(pid, interval);
    Ok((lines, delta))
}

/// Scans the memory of the process named in `args[1]` with the mode in `args[2]`.
///
/// Supported modes: `"-a"` (all regions), `"-h"` (heap), `"-v"` (verbose).
/// Optional `args[3]` can be `"-g"` for granular heap blocks or `"-json"` for JSON output.
pub fn scan(args: Vec<&str>) -> Result<ScanResult, String> {
    let queryp = args[1];
    let pid = find_pid(queryp.to_string())?;
    let mode = args[2];
    let granular = args.get(3).map(|a| a == &"-g").unwrap_or(false);
    let json = args.get(3).map(|a| a == &"-json").unwrap_or(false);
    let output = args.get(4).cloned();
    let lines = scan_with_modes_tui(&mode.to_string(), pid, json, output);
    let raw = get_heap_blocks(pid, granular);

    #[cfg(target_os = "windows")]
    let (pointer_blocks, referenced_blocks) = crate::os::find_blocks_with_pointers(pid, &raw);

    #[cfg(not(target_os = "windows"))]
    let (pointer_blocks, referenced_blocks) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );

    // get memory usage from sysinfo
    use sysinfo::System;
    let sys = System::new_all();
    let memory_mb = sys
        .processes()
        .values()
        .find(|p| p.pid().as_u32() == pid)
        .map(|p| p.memory() / 1024 / 1024)
        .unwrap_or(0);

    // if heap mode, collect block data for the TUI panels
    let (blocks, used_bytes, free_bytes, frag) = if mode == "-h" {
        let used_bytes: usize = raw.iter().filter(|b| !b.is_free).map(|b| b.size).sum();
        let free_bytes: usize = raw.iter().filter(|b| b.is_free).map(|b| b.size).sum();
        let largest_free = raw
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

        (raw, used_bytes, free_bytes, frag)
    } else {
        (vec![], 0, 0, 0.0)
    };

    Ok(ScanResult {
        lines,
        pid,
        memory_mb,
        blocks,
        used_bytes,
        free_bytes,
        frag,
        pointer_blocks,
        referenced_blocks,
    })
}

/// Lists loaded modules for the process named in `args[1]`, with an optional mode flag in `args[2]`.
///
/// Pass `"-t"` as the flag to restrict output to tampered or injected modules.
pub fn modules(args: Vec<&str>) -> Result<Vec<String>, String> {
    let mem = os::provider();
    let queryp = args[1];
    let pid = find_pid(queryp.to_string()).map_err(|e| e.to_string())?;
    let mut flag = "".to_string();
    if args.len() == 3 {
        flag = args[2].to_string();
    }
    let mut output: Vec<String> = vec![];
    let results = mem.list_modules(pid, flag).unwrap_or_default();
    output = results
        .into_iter()
        .map(|result| format!("{}: {:?}", result.name, result.status))
        .collect();
    Ok(output)
}

fn find_pid(name: String) -> Result<u32, String> {
    use crate::utils::process::{FuzzyMatch, fuzzy_find_pid};
    match fuzzy_find_pid(&name) {
        FuzzyMatch::Found(pid) => Ok(pid),
        FuzzyMatch::NotFound => Err(format!("process '{}' not found", name)),
        FuzzyMatch::Ambiguous(candidates) => {
            let names: Vec<&str> = candidates.iter().map(|(n, _)| n.as_str()).collect();
            Err(format!(
                "'{}' matches multiple processes: {}. Use a more specific name.",
                name,
                names.join(", ")
            ))
        }
    }
}

/// Returns a formatted list of running processes sorted by memory usage, up to the top 20.
///
/// An optional name filter can be provided as `args[1]`.
pub fn list_processes(args: Vec<&str>) -> Result<Vec<String>, String> {
    let mut output: Vec<String> = vec![];
    use sysinfo::System;
    let sys = System::new_all();
    let filter = args.get(1).map(|s| s.to_lowercase());
    let mut processes: Vec<_> = sys
        .processes()
        .values()
        .filter(|p| process_is_visible(p, filter.as_deref()))
        .collect();
    processes.sort_by_key(|b| std::cmp::Reverse(b.memory()));

    output.push(format!("{:<8} {:<30} {}", "PID", "NAME", "MEMORY"));
    output.push("-".repeat(50).to_string());
    for process in processes.iter().take(20) {
        output.push(format!(
            "{:<8} {:<30} {}",
            process.pid().as_u32(),
            process.name().to_string_lossy(),
            format_bytes(process.memory()),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{is_worker_thread_name, process_name_is_visible};

    #[test]
    fn detects_rayon_worker_threads() {
        assert!(is_worker_thread_name("rayon-worker"));
        assert!(is_worker_thread_name("rayon-worker-3"));
        assert!(!is_worker_thread_name("worker-service"));
    }

    #[test]
    fn hides_worker_threads_before_filtering() {
        assert!(!process_name_is_visible("rayon-worker", None));
        assert!(!process_name_is_visible("rayon-worker", Some("rayon")));
        assert!(process_name_is_visible("cargo", Some("car")));
    }
}

fn get_heap_blocks(pid: u32, _granular: bool) -> Vec<HeapBlock> {
    let mem = os::provider();
    #[cfg(target_os = "windows")]
    {
        if _granular {
            crate::os::walk_heap_granular(pid)
        } else {
            mem.walk_heap(pid).unwrap_or_default()
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        mem.walk_heap(pid).unwrap_or_default()
    }
}
