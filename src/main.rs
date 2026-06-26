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
use mvis::core::scan::{leak_command, leak_m_command, scan_with_modes};
use mvis::os;
use mvis::os::MemoryProvider;
use mvis::ui::commands::process_is_visible;
use mvis::ui::tui::tui_main;
use mvis::utils::error::AppError;
use mvis::utils::formatting::format_bytes;
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
fn run() -> Result<(), AppError> {
    let mut args: Vec<String> = env::args().collect();

    // Determine theme precedence: --theme flag -> MVIS_THEME -> dark (default)
    let mut theme_kind = mvis::ui::theme::ThemeKind::default();

    if let Ok(env_theme) = env::var("MVIS_THEME")
        && let Some(t) = mvis::ui::theme::ThemeKind::parse(&env_theme)
    {
        theme_kind = t;
    }

    if let Some(pos) = args.iter().position(|a| a == "--theme") {
        if pos + 1 < args.len() {
            if let Some(t) = mvis::ui::theme::ThemeKind::parse(&args[pos + 1]) {
                theme_kind = t;
            } else {
                eprintln!(
                    "warning: unknown theme '{}', falling back to default",
                    args[pos + 1]
                );
            }
            args.remove(pos);
            args.remove(pos);
        } else {
            eprintln!("warning: --theme requires a value");
            args.remove(pos);
        }
    }

    if args.len() <= 1 {
        mvis::ui::tui::tui_main(theme_kind).map_err(|e| AppError::Other(e.to_string()))?;
        return Ok(());
    }

    let command = get_arg(&args, 1, "command")?;
    let mem = os::provider();
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
            let interval = parse_positive_u64_arg(&args, 3, "interval")?;
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            leak_command(pid, interval);
        }
        "leak-m" => {
            let interval = parse_positive_u64_arg(&args, 3, "interval")?;
            let samples = parse_positive_u64_arg(&args, 4, "samples")?;
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            leak_m_command(pid, interval, samples);
        }
        "list" => {
            use sysinfo::System;
            let sys = System::new_all();
            let filter = args.get(2).map(|s| s.to_lowercase());
            let mut processes: Vec<_> = sys
                .processes()
                .values()
                .filter(|p| process_is_visible(p, filter.as_deref()))
                .collect();
            processes.sort_by_key(|b| std::cmp::Reverse(b.memory()));

            println!("{:<8} {:<30} MEMORY", "PID", "NAME");
            println!("{}", "-".repeat(50));
            for process in processes.iter().take(20) {
                println!(
                    "{:<8} {:<30} {}",
                    process.pid().as_u32(),
                    process.name().to_string_lossy(),
                    format_bytes(process.memory()),
                );
            }
        }
        "modules" => {
            let name = get_arg(&args, 2, "process name")?;
            let pid = find_pid(name.to_string())?;
            let _empty = String::new();
            let flag = args.get(3).map(|s| s.as_str()).unwrap_or("").to_string();

            let modules = mem.list_modules(pid, flag.to_string()).unwrap_or_default();
            println!("{:<18} {:<10} {:<10} NAME", "ADDRESS", "SIZE", "STATUS");
            println!("{}", "-".repeat(70));

            for m in &modules {
                let status = match m.status {
                    mvis::types::ModuleStatus::Ok => "\x1b[32mOK\x1b[0m",
                    mvis::types::ModuleStatus::Tampered => "\x1b[31mTAMPERED\x1b[0m",
                    mvis::types::ModuleStatus::Injected => "\x1b[33mINJECTED\x1b[0m",
                    mvis::types::ModuleStatus::Modified => "\x1b[34mMODIFIED\x1b[0m",
                    mvis::types::ModuleStatus::Unreadable => "\x1b[90mUNREADABLE\x1b[0m",
                };
                println!(
                    "0x{:<16x} {:<10} {:<10} {}",
                    m.base,
                    format_bytes(m.size as u64),
                    status,
                    m.name,
                );
            }

            let tampered: Vec<_> = modules
                .iter()
                .filter(|m| matches!(m.status, mvis::types::ModuleStatus::Tampered))
                .collect();
            let injected: Vec<_> = modules
                .iter()
                .filter(|m| matches!(m.status, mvis::types::ModuleStatus::Injected))
                .collect();

            println!();
            if tampered.is_empty() && injected.is_empty() {
                println!("\x1b[32mall modules appear clean\x1b[0m");
            } else {
                if !tampered.is_empty() {
                    println!(
                        "\x1b[31m{} tampered module(s) detected\x1b[0m",
                        tampered.len()
                    );
                }
                if !injected.is_empty() {
                    println!(
                        "\x1b[33m{} injected module(s) detected\x1b[0m",
                        injected.len()
                    );
                }
            }
        }
        "help" | "--help" | "-h" => match args.get(2).map(|s| s.as_str()) {
            Some("scan") => print_help_scan(),
            Some("leak") => print_help_leak(),
            Some("leak-m") => print_help_leak_m(),
            Some("list") => print_help_list(),
            Some("modules") => print_help_modules(),
            #[cfg(target_os = "windows")]
            Some("wintrace") => print_help_wintrace(),
            _ => print_help_all(),
        },
        "version" | "--version" | "-v" => {
            println!("{}", mvis::VERSION);
        }
        "trace" => {
            let queryp = get_arg(&args, 2, "process name")?;
            let pid = find_pid(queryp.to_string())?;
            let regions = mem.walk_regions(pid).unwrap_or_default();
            mvis::core::scan::stack_trace(pid, &regions);
        }
        "tui" => {
            let _ = tui_main(theme_kind);
        }
        _ => {
            return Err(AppError::UnknownCommand(command.to_string()));
        }
    }
    Ok(())
}

/// Finds a process PID by name.
///
/// Tries an exact case-insensitive match first. If that fails, falls back to a
/// case-insensitive substring search. When a single distinct process name matches
/// the query the corresponding PID is returned. When multiple distinct names match,
/// the user is shown a numbered list and prompted to choose one interactively.
fn find_pid(name: String) -> Result<u32, AppError> {
    use mvis::utils::process::{FuzzyMatch, fuzzy_find_pid};
    match fuzzy_find_pid(&name) {
        FuzzyMatch::Found(pid) => Ok(pid),
        FuzzyMatch::NotFound => Err(AppError::ProcessNotFound(name)),
        FuzzyMatch::Ambiguous(candidates) => {
            println!("Multiple processes match '{}':", name);
            for (i, (pname, pid)) in candidates.iter().enumerate() {
                println!("  [{}] {} (PID {})", i + 1, pname, pid);
            }
            use std::io::{self, Write};
            print!("Select [1-{}]: ", candidates.len());
            io::stdout()
                .flush()
                .map_err(|e| AppError::Other(e.to_string()))?;
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| AppError::Other(e.to_string()))?;
            let choice: usize = input
                .trim()
                .parse::<usize>()
                .map_err(|_| AppError::InvalidArg("invalid selection".to_string()))?;
            if choice < 1 || choice > candidates.len() {
                return Err(AppError::InvalidArg(format!(
                    "selection must be between 1 and {}",
                    candidates.len()
                )));
            }
            Ok(candidates[choice - 1].1)
        }
    }
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
/// * `Err(AppError)` - If the argument is missing, with a helpful message
fn get_arg<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a str, AppError> {
    args.get(index)
        .map(|s| s.as_str())
        .ok_or_else(|| AppError::MissingArg(name.to_string()))
}

fn parse_positive_u64_arg(args: &[String], index: usize, name: &str) -> Result<u64, AppError> {
    let value = get_arg(args, index, name)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| AppError::InvalidArg(format!("{} must be a positive number", name)))?;
    if parsed == 0 {
        return Err(AppError::InvalidArg(format!(
            "{} must be greater than 0",
            name
        )));
    }
    Ok(parsed)
}

fn print_help_all() {
    println!("Usage: mvis <command> [args]");
    println!();
    println!("Commands:");
    println!("  {:<14} Analyze memory layout of a process", "scan");
    println!("  {:<14} Detect memory leaks in a process", "leak");
    println!("  {:<14} Detect leaks across multiple samples", "leak-m");
    println!("  {:<14} Show running processes by memory usage", "list");
    println!("  {:<14} List loaded modules for a process", "modules");
    #[cfg(target_os = "windows")]
    println!("  {:<14} Capture a stack trace (Windows only)", "wintrace");
    println!("  {:<14} Launch the interactive TUI", "tui");
    println!("  {:<14} Show command help", "help [cmd]");
    println!("  {:<14} Show version", "version");
    println!();
    println!("Options:");
    println!(
        "  {:<14} Set UI theme (dark, light, deuteranopia, protanopia)",
        "--theme <name>"
    );
    println!();
    println!("Theme precedence:");
    println!("  1. --theme flag");
    println!("  2. MVIS_THEME environment variable");
    println!("  3. dark (default)");
    println!();
    println!("Run 'mvis help <command>' for command-specific help.");
}

fn print_help_scan() {
    println!("Usage: mvis scan <process> <mode> [-json] [output]");
    println!();
    println!("Analyze the memory layout of a running process.");
    println!();
    println!("Arguments:");
    println!("  <process>   Process name (e.g. notepad.exe)");
    println!("  <mode>      -h  Heap mode");
    println!("              -a  All regions");
    println!("              -v  Verbose output");
    println!("  [-json]     Output results as JSON");
    println!("  [output]    Write output to a file path");
    println!();
    println!("Examples:");
    println!("  mvis scan notepad.exe -h");
    println!("  mvis scan notepad.exe -a -json results.json");
}

fn print_help_leak() {
    println!("Usage: mvis leak <process> <interval>");
    println!();
    println!("Monitor a process for memory leaks over time.");
    println!();
    println!("Arguments:");
    println!("  <process>    Process name (e.g. my_app.exe)");
    println!("  <interval>   Sampling interval in seconds (must be > 0)");
    println!();
    println!("Examples:");
    println!("  mvis leak my_app.exe 10");
    println!("  mvis leak chrome.exe 5");
}

fn print_help_leak_m() {
    println!("Usage: mvis leak-m <process> <interval> <samples>");
    println!();
    println!("Detect memory leaks using a fixed number of samples.");
    println!();
    println!("Arguments:");
    println!("  <process>    Process name (e.g. my_app.exe)");
    println!("  <interval>   Seconds between samples (must be > 0)");
    println!("  <samples>    Number of samples to collect (must be > 0)");
    println!();
    println!("Examples:");
    println!("  mvis leak-m my_app.exe 5 12");
}

fn print_help_list() {
    println!("Usage: mvis list [filter]");
    println!();
    println!("Show the top 20 running processes sorted by memory usage.");
    println!();
    println!("Arguments:");
    println!("  [filter]   Optional name filter (case-insensitive)");
    println!();
    println!("Examples:");
    println!("  mvis list");
    println!("  mvis list chrome");
}

fn print_help_modules() {
    println!("Usage: mvis modules <process> <flag>");
    println!();
    println!("List loaded modules for a process and check for tampering.");
    println!();
    println!("Arguments:");
    println!("  <process>   Process name (e.g. notepad.exe)");
    println!("  <flag>      -t  Include tamper detection");
    println!();
    println!("Examples:");
    println!("  mvis modules notepad.exe -t");
}

#[cfg(target_os = "windows")]
fn print_help_wintrace() {
    println!("Usage: mvis wintrace <process>");
    println!();
    println!("Capture a stack trace for a running process (Windows only).");
    println!();
    println!("Arguments:");
    println!("  <process>   Process name (e.g. my_app.exe)");
    println!();
    println!("Examples:");
    println!("  mvis wintrace my_app.exe");
}

#[cfg(test)]
mod tests {
    use super::{find_pid, get_arg, parse_positive_u64_arg};
    use mvis::utils::error::AppError;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn get_arg_returns_existing_value() {
        let args = args(&["mvis", "leak", "app", "5"]);

        assert_eq!(get_arg(&args, 2, "process name"), Ok("app"));
    }

    #[test]
    fn get_arg_reports_missing_value() {
        let args = args(&["mvis", "leak"]);

        assert_eq!(
            get_arg(&args, 2, "process name"),
            Err(AppError::MissingArg("process name".to_string()))
        );
    }

    #[test]
    fn parse_positive_u64_arg_accepts_positive_values() {
        let args = args(&["mvis", "leak", "app", "5"]);

        assert_eq!(parse_positive_u64_arg(&args, 3, "interval"), Ok(5));
    }

    #[test]
    fn parse_positive_u64_arg_rejects_zero() {
        let args = args(&["mvis", "leak", "app", "0"]);

        assert_eq!(
            parse_positive_u64_arg(&args, 3, "interval"),
            Err(AppError::InvalidArg(
                "interval must be greater than 0".to_string()
            ))
        );
    }

    #[test]
    fn parse_positive_u64_arg_rejects_negative_values() {
        let args = args(&["mvis", "leak", "app", "-5"]);

        assert_eq!(
            parse_positive_u64_arg(&args, 3, "interval"),
            Err(AppError::InvalidArg(
                "interval must be a positive number".to_string()
            ))
        );
    }

    #[test]
    fn parse_positive_u64_arg_reports_missing_values() {
        let args = args(&["mvis", "leak", "app"]);

        assert_eq!(
            parse_positive_u64_arg(&args, 3, "interval"),
            Err(AppError::MissingArg("interval".to_string()))
        );
    }

    #[test]
    fn find_pid_reports_missing_process() {
        let result = find_pid("zzzz_does_not_exist_9999_zzzz".to_string());

        assert_eq!(
            result,
            Err(AppError::ProcessNotFound(
                "zzzz_does_not_exist_9999_zzzz".to_string()
            ))
        );
    }
}

/// Checks if the current process is running with elevated privileges.
///
/// On Windows: checks for admin token elevation.
/// On Linux: checks if effective user ID is root (0).
#[cfg(target_os = "windows")]
#[allow(dead_code)]
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
