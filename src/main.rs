//! # mvis - Memory Visualizer
//!
//! A cross-platform memory diagnostic CLI tool.
//!
//! ## Usage
//! ```
//! mvis scan <process> <mode>
//! mvis leak <process> <interval>
//! mvis leak-m <process> <interval> <samples>
//! mvis list [filter]
//! ```
//!
use mvis::scan::{leak_command, leak_m_command, scan_with_modes};
use std::env;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

/// Entry point for all CLI commands.
///
/// Parses arguments and dispatches to the appropriate handler.
/// Returns `Err(String)` with a human-readable message on failure.
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
            let filter = args.get(2).map(|s| s.to_lowercase());
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

            println!("{:<8} {:<30} {}", "PID", "NAME", "MEMORY");
            println!("{}", "-".repeat(50));
            for process in processes.iter().take(20) {
                println!(
                    "{:<8} {:<30} {} MB",
                    process.pid().as_u32(),
                    process.name().to_string_lossy(),
                    process.memory() / 1024 / 1024,
                );
            }
        }
        "help" | "--help" | "-h" => {
            println!("commands");
            println!("scan [app.exe] [modes] [json] [output]");
            println!("leak [app.exe] [duration]");
            println!("leak-m [app.exe] [duration] [samples]");
            #[cfg(target_os = "windows")]
            println!("wintrace [app.exe]");
            println!("help");
            println!("version");
            println!("list [filter]");
            println!("");
            println!("modes");
            println!("-h :Heap Mode");
            println!("-a :All Mode");
            println!("-v :Verbose Mode");
        }
        "version" | "--version" | "-v" => {
            println!("Mvis v0.1.0");
        }
        #[cfg(target_os = "windows")]
        "wintrace" => {
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            let regions = mvis::os::walk_regions(pid);
            match mvis::stack_trace::StackTrace::capture(pid, &regions) {
                Ok(trace) => {
                    println!("stack trace for {} (pid: {})", queryp, pid);
                    println!("{}", "-".repeat(60));
                    for frame in &trace.frames {
                        println!("  0x{:x}  {}", frame.instruction_pointer, frame.symbol);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        _ => {
            return Err(format!("unknown command '{}' — run 'mvis --help'", command));
        }
    }
    Ok(())
}

/// Finds a process PID by name, case-insensitive.
///
/// # Arguments
/// * `name` - The process name to search for (e.g. "notepad.exe")
///
/// # Returns
/// * `Ok(u32)` - The PID of the first matching process
/// * `Err(String)` - If no process with that name is found
///
/// # Example
/// ```
/// let pid = find_pid("notepad.exe".to_string())?;
/// ```
fn find_pid(name: String) -> Result<u32, String> {
    use sysinfo::System;
    let sys = System::new_all();
    sys.processes()
        .values()
        .find(|p| p.name().to_string_lossy().to_lowercase() == name.to_lowercase())
        .map(|p| p.pid().as_u32())
        .ok_or_else(|| format!("process '{}' not found", name))
}

/// Gets a CLI argument by index.
///
/// # Arguments
/// * `args` - The full argument list
/// * `index` - Which argument to get
/// * `name` - Human-readable name for error messages
///
/// # Returns
/// * `Ok(&str)` - The argument value
/// * `Err(String)` - If the argument is missing, with a helpful message
fn get_arg<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("missing argument: {}", name))
}

/// Checks if the current process is running with elevated privileges.
///
/// On Windows: checks for admin token elevation.
/// On Linux: checks if effective user ID is root (0).
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
        )
        .is_err()
        {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}

#[cfg(target_os = "linux")]
fn is_elevated() -> bool {
    // on linux check if root
    unsafe { libc::geteuid() == 0 }
}
