// src/main.rs
use memory_visualizer::scan::{scan_with_modes, leak_command};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let query = &args[1];

    match query.as_str() {
        "scan" => {
            let queryp = &args[2];
            let pid = find_pid(queryp.to_string()).expect("failed to find process");
            let mode = &args[3];
            scan_with_modes(mode, pid);
        }
        "leak" => {
            let queryp = &args[2];
            let pid = find_pid(queryp.to_string()).expect("failed to find process");
            let interval: u64 = args[3].parse().unwrap_or(5);  // seconds between snapshots
            leak_command(pid, interval);
        }
        "--help" => {
            println!("commands");
            println!("scan [app.exe] [modes]");
            println!("leak [app.exe] [duration]");
            println!("--help");
            println!("");
            println!("modes");
            println!("-h :Heap Mode");
            println!("-a :All Mode");
        }
        "--version" => {
            println!("Mvis v0.0.1");
        }
        _ => {
            println!("Invalid Command: {}", query);
        }
    }
}

fn find_pid(name: String) -> Result<u32, String>{
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    for (pid, process) in sys.processes() {
        if *process.name() == *name {
            let process_id = pid.as_u32();
            return Ok(process_id);
        }
    }
    Err("Can't find process name".to_string())
}