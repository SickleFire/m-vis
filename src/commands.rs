use crate::scan::scan_with_modes_tui;
use ratatui::text::Line;

use crate::types::HeapBlock;

pub struct ScanResult {
    pub lines: Vec<Line<'static>>,
    pub pid: u32,
    pub memory_mb: u64,
    // heap data — only populated when mode is "-h"
    pub blocks: Vec<HeapBlock>,
    pub used_bytes: usize,
    pub free_bytes: usize,
    pub frag: f64,
}

pub fn scan(args: Vec<&str>) -> Result<ScanResult, String> {
    let queryp = args[1];
    let pid = find_pid(queryp.to_string())?;
    let mode = args[2];
    let json = args.get(3).map(|a| a == &"-json").unwrap_or(false);
    let output = args.get(4).cloned();
    let lines = scan_with_modes_tui(&mode.to_string(), pid, json, output);

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
        let raw = crate::os::walk_heap(pid);

        let used_bytes: usize = raw.iter().filter(|b| !b.is_free).map(|b| b.size).sum();
        let free_bytes: usize = raw.iter().filter(|b| b.is_free).map(|b| b.size).sum();
        let total = used_bytes + free_bytes;
        let frag = if total > 0 {
            free_bytes as f64 / total as f64 * 100.0
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
    })
}

fn find_pid(name: String) -> Result<u32, String> {
    use sysinfo::System;
    let sys = System::new_all();
    sys.processes()
        .values()
        .find(|p| p.name().to_string_lossy().to_lowercase() == name.to_lowercase())
        .map(|p| p.pid().as_u32())
        .ok_or_else(|| format!("process '{}' not found", name))
}

pub fn list_processes(args: Vec<&str>) -> Result<Vec<String>, String> {
    let mut output: Vec<String> = vec![];
    use sysinfo::System;
    let sys = System::new_all();
    let filter = args.get(1).map(|s| s.to_lowercase());
    let mut processes: Vec<_> = sys
        .processes()
        .values()
        .filter(|p| {
            filter.as_ref().map_or(true, |f| {
                p.name().to_string_lossy().to_lowercase().contains(f)
            })
        })
        .collect();
    processes.sort_by(|a, b| b.memory().cmp(&a.memory()));

    output.push(format!("{:<8} {:<30} {}", "PID", "NAME", "MEMORY"));
    output.push(format!("{}", "-".repeat(50)));
    for process in processes.iter().take(20) {
        output.push(format!(
            "{:<8} {:<30} {} MB",
            process.pid().as_u32(),
            process.name().to_string_lossy(),
            process.memory() / 1024 / 1024,
        ));
    }
    Ok(output)
}
