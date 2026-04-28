// src/main.rs
use mvis::scan::{scan_with_modes, leak_command, leak_m_command};
use std::env;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let command = get_arg(&args, 1, "command")?;

    match command {
        "scan" => {
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            let mode = get_arg(&args, 3, "mode (-a, -h, -v)")?;
            let json = args.get(4).map(|a| a == "-json").unwrap_or(false);
            let output = args.get(5).cloned();
            scan_with_modes(&mode.to_string(), pid, json, output);
        }
        "leak" => {
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            let interval: u64 = get_arg(&args, 3, "interval (seconds)")?
                .parse::<u64>()
                .map_err(|_| "interval must be a number".to_string())?;
            leak_command(pid, interval);
        }
        "leak-m" => {
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            let interval: u64 = get_arg(&args, 3, "interval (seconds)")?
                .parse::<u64>()
                .map_err(|_| "interval must be a number".to_string())?;
            let samples: u64 = get_arg(&args, 4, "samples")?
                .parse::<u64>()
                .map_err(|_| "samples must be a number".to_string())?;
            leak_m_command(pid, interval, samples);
        }
        "list" => {
            use sysinfo::System;
            let sys = System::new_all();
            println!("[PID]  [NAME]");
            for (pid, process) in sys.processes(){
                //TODO sort by memory usage
                println!("{} {:?}", pid, process.name());
            }
        }
        "etw-leak" => {
            if !is_elevated() {
                return Err("etw-leak requires administrator privileges\nrun: sudo mvis etw-leak <process>".to_string());
            }
            // rest of implementation
        }
        "--help" => {
            println!("commands");
            println!("scan [app.exe] [modes] [json] [output]");
            println!("leak [app.exe] [duration]");
            println!("leak-m [app.exe] [duration] [samples]");
            println!("--help");
            println!("");
            println!("modes");
            println!("-h :Heap Mode");
            println!("-a :All Mode");
            println!("-v :Verbose Mode");
        }
        "--version" => {
            println!("Mvis v0.0.5");
        }
        _ => {
            return Err(format!("unknown command '{}' — run 'mvis --help'", command));
        }
    }
    Ok(())
}

fn find_pid(name: String) -> Result<u32, String>{
    use sysinfo::System;
    let sys = System::new_all();
    sys.processes()
        .values()
        .find(|p| p.name().to_string_lossy() == name)
        .map(|p| p.pid().as_u32())
        .ok_or_else(|| format!("process '{}' not found", name))
}

fn get_arg<'a>(args: &'a[String], index: usize, name: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("missing argument: {}", name))
}

fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, 
        TOKEN_ELEVATION, TOKEN_QUERY
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken
    };

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        if GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut size,
        ).is_err() {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}