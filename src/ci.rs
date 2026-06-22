use crate::core::scan::{diff_heap_size, heap_mode};
use crate::export::FormatType;
use crate::utils::error::AppError;
use crate::utils::process::{FuzzyMatch, fuzzy_find_pid};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use sysinfo::System;

enum CiTarget {
    Spawn { command: String, args: Vec<String> },
    AttachPid(u32),
    AttachName(String),
}

struct CiArgs {
    target: CiTarget,
    max_memory: Option<u64>,
    leak_check: bool,
    duration: Option<Duration>,
    format: Option<FormatType>,
}

pub fn ci_main(args: &[String]) -> i32 {
    let parsed: CiArgs = match parse_ci_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    let (pid, mut child) = match resolve_target(&parsed.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    // baseline for leak check
    let baseline = if parsed.leak_check {
        heap_mode(pid).ok()
    } else {
        None
    };

    let start = Instant::now();
    let poll_interval = Duration::from_millis(1000);
    let mut sys = System::new_all();
    let mut exit_code = 0;

    loop {
        // Check if duration elapsed
        if let Some(dur) = parsed.duration {
            if start.elapsed() >= dur {
                break;
            }
        }

        // Check if process exited
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        if sys.process(sysinfo::Pid::from_u32(pid)).is_none() {
            // Process exited natively
            break;
        }

        // Wait, if it's our spawned child, check try_wait()
        if let Some(ref mut c) = child {
            if let Ok(Some(_)) = c.try_wait() {
                break;
            }
        }

        // Enforce max_memory
        if let Some(max_mem) = parsed.max_memory {
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let current_mem = process.memory(); // memory in bytes
                if current_mem > max_mem {
                    eprintln!(
                        "error: memory limit exceeded. Max: {}, Current: {}",
                        max_mem, current_mem
                    );
                    exit_code = 2;
                    break;
                }
            }
        }

        // Enforce leak_check by comparing with baseline
        if parsed.leak_check {
            if let Some(ref prev) = baseline {
                if let Ok(current) = heap_mode(pid) {
                    let growth = diff_heap_size(prev, &current);
                    if growth > 0 {
                        eprintln!("error: memory leak detected! Heap grew by {} bytes", growth);
                        exit_code = 2;
                        break;
                    }
                }
            }
        }

        std::thread::sleep(poll_interval);
    }

    // Cleanup spawned child if any
    if let Some(mut c) = child {
        let _ = c.kill();
        let _ = c.wait();
    }

    exit_code
}

/// Turns a target spec into a live PID — spawning a child or resolving an
/// already-running process, depending on which was requested.
fn resolve_target(target: &CiTarget) -> Result<(u32, Option<Child>), AppError> {
    match target {
        CiTarget::Spawn { command, args } => {
            let child = Command::new(command)
                .args(args)
                .spawn()
                .map_err(|e| AppError::Other(format!("failed to launch '{}': {}", command, e)))?;
            let pid = child.id();
            Ok((pid, Some(child)))
        }
        CiTarget::AttachPid(pid) => Ok((*pid, None)),
        CiTarget::AttachName(name) => match fuzzy_find_pid(name) {
            FuzzyMatch::Found(pid) => Ok((pid, None)),
            FuzzyMatch::NotFound => Err(AppError::ProcessNotFound(name.clone())),
            FuzzyMatch::Ambiguous(_) => Err(AppError::InvalidArg(format!(
                "'{}' matches multiple processes — use --pid for an exact match",
                name
            ))),
        },
    }
}

fn parse_ci_args(args: &[String]) -> Result<CiArgs, AppError> {
    let mut max_memory = None;
    let mut leak_check = false;
    let mut duration = None;
    let mut target = None;
    let mut format = None;

    let mut i = 2; // skip "mvis" and "ci"
    while i < args.len() {
        match args[i].as_str() {
            "--max-memory" => {
                if i + 1 < args.len() {
                    let val = args[i + 1]
                        .parse::<u64>()
                        .map_err(|_| AppError::InvalidArg("invalid --max-memory".into()))?;
                    max_memory = Some(val);
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--max-memory".into()));
                }
            }
            "--leak-check" => {
                leak_check = true;
                i += 1;
            }
            "--duration" => {
                if i + 1 < args.len() {
                    let val = args[i + 1]
                        .parse::<u64>()
                        .map_err(|_| AppError::InvalidArg("invalid --duration".into()))?;
                    duration = Some(Duration::from_secs(val));
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--duration".into()));
                }
            }
            "--pid" => {
                if i + 1 < args.len() {
                    let val = args[i + 1]
                        .parse::<u32>()
                        .map_err(|_| AppError::InvalidArg("invalid --pid".into()))?;
                    target = Some(CiTarget::AttachPid(val));
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--pid".into()));
                }
            }
            "--spawn" => {
                if i + 1 < args.len() {
                    let cmd = args[i + 1].clone();
                    let cmd_args = if i + 2 < args.len() {
                        args[i + 2..].to_vec()
                    } else {
                        vec![]
                    };
                    target = Some(CiTarget::Spawn {
                        command: cmd,
                        args: cmd_args,
                    });
                    break;
                } else {
                    return Err(AppError::MissingArg("--spawn".into()));
                }
            }
            "--format" => {
                //choose which kind of format json, csv, junit
                if i + 1 < args.len() {
                    let parsed_format = args[i + 1].as_str();
                    match parsed_format {
                        "json" => {
                            format = Some(FormatType::Json);
                        }
                        "junit" => {
                            format = Some(FormatType::Junit);
                        }
                        "csv" => {
                            format = Some(FormatType::CSV);
                        }
                        other => {
                            return Err(AppError::InvalidArg(format!(
                                "Unknown argument: {}",
                                other
                            )));
                        }
                    }
                } else {
                    return Err(AppError::MissingArg("--format".into()));
                }
            }
            "--output" => {
                //to write results
                todo!()
            }
            other => {
                if target.is_none() {
                    target = Some(CiTarget::AttachName(other.to_string()));
                    i += 1;
                } else {
                    return Err(AppError::InvalidArg(format!("Unknown argument: {}", other)));
                }
            }
        }
    }

    let target = target.unwrap_or_else(|| CiTarget::AttachName("".to_string()));

    Ok(CiArgs {
        target,
        max_memory,
        leak_check,
        duration,
        format,
    })
}
