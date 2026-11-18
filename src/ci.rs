use crate::core::scan::{diff_heap_size, heap_mode};
use crate::export::{
    CheckResult, FormatType, heap_to_csv_file, heap_to_json_file, heap_to_junit_file,
};
use crate::utils::error::AppError;
use crate::utils::process::{FuzzyMatch, fuzzy_find_pid};
use std::collections::VecDeque;
use std::error::Error;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use sysinfo::System;

// How far back the rolling window looks when computing growth rate.
const GROWTH_WINDOW_SECS: u64 = 5;

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
    output: Option<String>,
    diff_only: bool,
    /// Bytes per second. Fail if the rolling-window growth rate exceeds this.
    growth_rate: Option<u64>,
    sample_interval: Option<u64>,
    warm_up: Option<u64>,
}

pub fn ci_main(args: &[String]) -> i32 {
    let mut last_captured_heap = None;

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

    let warmup_duration = Duration::from_secs(parsed.warm_up.unwrap_or(0));
    std::thread::sleep(warmup_duration);

    // Baseline for leak check — taken once before the loop.
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let baseline_rss = if parsed.leak_check {
        sys.process(sysinfo::Pid::from_u32(pid)).map(|p| p.memory())
    } else {
        None
    };
    let baseline = if parsed.leak_check {
        heap_mode(pid).ok()
    } else {
        None
    };

    if parsed.diff_only && !parsed.leak_check {
        eprintln!("error: --diff-only requires --leak-check to be active");
        return 1;
    }

    let start = Instant::now();
    let poll_interval = Duration::from_millis(parsed.sample_interval.unwrap_or(1000));
    let mut exit_code = 0;
    let mut failed_check: Option<(&'static str, String)> = None;

    // Rolling window for --growth-rate: stores (sample_time, total_heap_bytes).
    // Entries older than GROWTH_WINDOW_SECS are evicted each iteration.
    let mut heap_samples: VecDeque<(Instant, u64)> = VecDeque::new();

    loop {
        // Check if duration elapsed.
        if let Some(dur) = parsed.duration {
            if start.elapsed() >= dur {
                break;
            }
        }

        // Check if process exited.
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        if sys.process(sysinfo::Pid::from_u32(pid)).is_none() {
            break;
        }

        // If we spawned the child, also check try_wait().
        if let Some(ref mut c) = child {
            if let Ok(Some(_)) = c.try_wait() {
                break;
            }
        }

        // Enforce --max-memory.
        if let Some(max_mem) = parsed.max_memory {
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let current_mem = process.memory();
                if current_mem > max_mem {
                    eprintln!(
                        "error: memory limit exceeded. Max: {} MB, Current: {:.2} MB",
                        max_mem / (1024 * 1024),
                        current_mem as f64 / (1024.0 * 1024.0)
                    );
                    failed_check = Some((
                        "max-memory",
                        format!(
                            "limit {} MB exceeded, current {:.2} MB",
                            max_mem / (1024 * 1024),
                            current_mem as f64 / (1024.0 * 1024.0)
                        ),
                    ));
                    exit_code = 2;
                    break;
                }
            }
        }

        // Single heap snapshot for this tick — reused by both leak-check and
        // growth-rate so we only walk the heap once per iteration.
        let current_heap = heap_mode(pid).ok();

        // Enforce --leak-check.
        if parsed.leak_check {
            let heap_growth = match (&baseline, &current_heap) {
                (Some(prev), Some(current)) => diff_heap_size(prev, current),
                _ => 0,
            };

            if heap_growth > 0 {
                eprintln!(
                    "error: memory leak detected! Heap grew by {} bytes",
                    heap_growth
                );
                failed_check = Some(("leak-check", format!("heap grew by {} bytes", heap_growth)));
                exit_code = 2;
                break;
            }

            if heap_growth == 0
                && cfg!(target_os = "macos")
                && let (Some(baseline_rss), Some(process)) =
                    (baseline_rss, sys.process(sysinfo::Pid::from_u32(pid)))
            {
                let rss_growth = process.memory().saturating_sub(baseline_rss);
                if rss_growth > 0 {
                    eprintln!(
                        "error: memory leak detected! RSS grew by {} bytes",
                        rss_growth
                    );
                    failed_check =
                        Some(("leak-check", format!("RSS grew by {} bytes", rss_growth)));
                    exit_code = 2;
                    break;
                }
            }
        }

        // Enforce --growth-rate using a rolling window.
        if let Some(rate_limit) = parsed.growth_rate {
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let mem_bytes = process.memory();
                let now = Instant::now();
                heap_samples.push_back((now, mem_bytes));

                let window = Duration::from_secs(GROWTH_WINDOW_SECS);
                while heap_samples
                    .front()
                    .map(|(t, _)| now.duration_since(*t) > window)
                    .unwrap_or(false)
                {
                    heap_samples.pop_front();
                }

                if heap_samples.len() >= 2 {
                    let (oldest_time, oldest_bytes) = heap_samples.front().unwrap();
                    let elapsed_secs = now.duration_since(*oldest_time).as_secs_f64();

                    if elapsed_secs >= 1.0 {
                        let byte_delta = mem_bytes.saturating_sub(*oldest_bytes);
                        let rate = (byte_delta as f64 / elapsed_secs) as u64;

                        if rate > rate_limit {
                            eprintln!(
                                "error: heap growth rate exceeded. Limit: {} B/s, Current: {} B/s (over {:.1}s window)",
                                rate_limit, rate, elapsed_secs
                            );
                            failed_check = Some((
                                "growth-rate",
                                format!(
                                    "rate {} B/s exceeded limit {} B/s (over {:.1}s window)",
                                    rate, rate_limit, elapsed_secs
                                ),
                            ));
                            exit_code = 2;
                            break;
                        }
                    }
                }
            }
        }
        // Keep the latest heap snapshot for export.
        if let Some(current) = current_heap {
            last_captured_heap = Some(current);
        }

        std::thread::sleep(poll_interval);
    }

    let mut check_results: Vec<CheckResult> = Vec::new();
    if parsed.leak_check {
        let (passed, message) = match &failed_check {
            Some((name, msg)) if *name == "leak-check" => (false, Some(msg.clone())),
            _ => (true, None),
        };
        check_results.push(CheckResult {
            name: "leak-check".to_string(),
            passed,
            message,
        });
    }
    if parsed.growth_rate.is_some() {
        let (passed, message) = match &failed_check {
            Some((name, msg)) if *name == "growth-rate" => (false, Some(msg.clone())),
            _ => (true, None),
        };
        check_results.push(CheckResult {
            name: "growth-rate".to_string(),
            passed,
            message,
        });
    }
    if parsed.max_memory.is_some() {
        let (passed, message) = match &failed_check {
            Some((name, msg)) if *name == "max-memory" => (false, Some(msg.clone())),
            _ => (true, None),
        };
        check_results.push(CheckResult {
            name: "max-memory".to_string(),
            passed,
            message,
        });
    }

    // Export report if requested.
    if let Some(ref format_type) = parsed.format {
        let export_result: Option<(String, Result<(), Box<dyn Error>>)> = match format_type {
            FormatType::Junit => {
                let target_path = parsed
                    .output
                    .clone()
                    .unwrap_or_else(|| "heap_dump.xml".to_string());
                Some((
                    target_path.clone(),
                    heap_to_junit_file(&target_path, check_results),
                ))
            }
            FormatType::Json | FormatType::CSV => {
                if let Some(current_heap) = last_captured_heap {
                    let mut blocks = current_heap;
                    if parsed.diff_only {
                        if let Some(ref prev) = baseline {
                            blocks = blocks.into_iter().filter(|b| !prev.contains(b)).collect();
                        }
                    }
                    let target_path = parsed.output.clone().unwrap_or_else(|| match format_type {
                        FormatType::Json => "heap_dump.json".to_string(),
                        FormatType::CSV => "heap_dump.csv".to_string(),
                        FormatType::Junit => unreachable!(),
                    });
                    let result = match format_type {
                        FormatType::Json => heap_to_json_file(&target_path, blocks),
                        FormatType::CSV => heap_to_csv_file(&target_path, blocks),
                        FormatType::Junit => unreachable!(),
                    };
                    Some((target_path, result))
                } else {
                    eprintln!("warning: no heap snapshot was captured; skipping export");
                    None
                }
            }
        };

        if let Some((target_path, result)) = export_result {
            match result {
                Ok(_) => println!("Successfully wrote report to: {}", target_path),
                Err(e) => {
                    eprintln!("failed to export report to {}: {}", target_path, e);
                    if exit_code == 0 {
                        exit_code = 1;
                    }
                }
            }
        }
    }

    // Cleanup spawned child if any.
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
    let mut diff_only = false;
    let mut duration = None;
    let mut target = None;
    let mut format = None;
    let mut output = None;
    let mut growth_rate = None;
    let mut sample_interval = None;
    let mut warm_up = None;

    let mut i = 2; // skip "mvis" and "ci"
    while i < args.len() {
        match args[i].as_str() {
            "--max-memory" => {
                if i + 1 < args.len() {
                    let mb_val = args[i + 1]
                        .parse::<u64>()
                        .map_err(|_| AppError::InvalidArg("invalid --max-memory".into()))?;
                    max_memory = Some(mb_val * 1024 * 1024);
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--max-memory".into()));
                }
            }
            "--leak-check" => {
                leak_check = true;
                i += 1;
            }
            "--diff-only" => {
                diff_only = true;
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
                if i + 1 < args.len() {
                    let parsed_format = args[i + 1].as_str();
                    match parsed_format {
                        "json" => format = Some(FormatType::Json),
                        "junit" => format = Some(FormatType::Junit),
                        "csv" => format = Some(FormatType::CSV),
                        other => {
                            return Err(AppError::InvalidArg(format!("Unknown format: {}", other)));
                        }
                    }
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--format".into()));
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--output".into()));
                }
            }
            "--growth-rate" => {
                if i + 1 < args.len() {
                    let val = args[i + 1].parse::<u64>().map_err(|_| {
                        AppError::InvalidArg(
                            "invalid --growth-rate: expected bytes per second".into(),
                        )
                    })?;
                    growth_rate = Some(val);
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--growth-rate".into()));
                }
            }
            "--sample-interval" => {
                if i + 1 < args.len() {
                    let val = args[i + 1].parse::<u64>().ok().filter(|&v| v > 0)
                        .ok_or_else(|| AppError::InvalidArg(
                            "invalid --sample-interval: expected a positive number of milliseconds".into()
                        ))?;
                    sample_interval = Some(val);
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--sample-interval".into()));
                }
            }
            "--warmup" => {
                if i + 1 < args.len() {
                    let val = args[i + 1]
                        .parse::<u64>()
                        .ok()
                        .filter(|&v| v > 0)
                        .ok_or_else(|| {
                            AppError::InvalidArg(
                                "invalid --warmup: expected a positive number of seconds".into(),
                            )
                        })?;
                    warm_up = Some(val);
                    i += 2;
                } else {
                    return Err(AppError::MissingArg("--warmup".into()));
                }
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
        diff_only,
        duration,
        format,
        output,
        growth_rate,
        sample_interval,
        warm_up,
    })
}

pub fn compute_growth_rate(
    samples: &std::collections::VecDeque<(std::time::Instant, u64)>,
    now: std::time::Instant,
) -> Option<u64> {
    if samples.len() < 2 {
        return None;
    }
    let (oldest_time, oldest_bytes) = samples.front().unwrap();
    let (_, newest_bytes) = samples.back().unwrap();
    let elapsed = now.duration_since(*oldest_time).as_secs_f64();
    if elapsed < 1.0 {
        return None;
    }
    Some((newest_bytes.saturating_sub(*oldest_bytes) as f64 / elapsed) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::{Duration, Instant};

    #[test]
    fn rate_detected_correctly() {
        let now = Instant::now();
        let mut samples = VecDeque::new();
        samples.push_back((now - Duration::from_secs(5), 0));
        samples.push_back((now, 5 * 1024 * 1024)); // 1 MB/s over 5s
        let rate = compute_growth_rate(&samples, now).unwrap();
        assert!(rate > 900_000 && rate < 1_100_000); // ~1 MB/s
    }

    #[test]
    fn single_sample_returns_none() {
        let now = Instant::now();
        let mut samples = VecDeque::new();
        samples.push_back((now, 1024));
        assert!(compute_growth_rate(&samples, now).is_none());
    }

    #[test]
    fn sub_second_window_returns_none() {
        let now = Instant::now();
        let mut samples = VecDeque::new();
        samples.push_back((now - Duration::from_millis(500), 0));
        samples.push_back((now, 1024 * 1024));
        assert!(compute_growth_rate(&samples, now).is_none());
    }

    #[test]
    fn shrinking_heap_returns_zero() {
        let now = Instant::now();
        let mut samples = VecDeque::new();
        samples.push_back((now - Duration::from_secs(5), 10 * 1024 * 1024));
        samples.push_back((now, 5 * 1024 * 1024)); // heap shrank
        let rate = compute_growth_rate(&samples, now).unwrap();
        assert_eq!(rate, 0);
    }
    // --- parse_ci_args ---
    //
    // Helper: build a fake argv. parse_ci_args skips indices 0 and 1
    // (the "mvis" and "ci" positions), so real flags start at index 2.
    fn argv(rest: &[&str]) -> Vec<String> {
        let mut v = vec!["mvis".to_string(), "ci".to_string()];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn max_memory_converts_mb_to_bytes() {
        let args = argv(&["--max-memory", "64"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.max_memory, Some(64 * 1024 * 1024));
    }

    #[test]
    fn max_memory_rejects_non_numeric() {
        let args = argv(&["--max-memory", "not-a-number"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn max_memory_missing_value_errors() {
        let args = argv(&["--max-memory"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn leak_check_and_diff_only_flags_set() {
        let args = argv(&["--leak-check", "--diff-only"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert!(parsed.leak_check);
        assert!(parsed.diff_only);
    }

    #[test]
    fn duration_parses_seconds() {
        let args = argv(&["--duration", "30"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.duration, Some(Duration::from_secs(30)));
    }

    #[test]
    fn pid_target_parses() {
        let args = argv(&["--pid", "4242"]);
        let parsed = parse_ci_args(&args).unwrap();
        match parsed.target {
            CiTarget::AttachPid(pid) => assert_eq!(pid, 4242),
            _ => panic!("expected AttachPid target"),
        }
    }

    #[test]
    fn pid_rejects_non_numeric() {
        let args = argv(&["--pid", "abc"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn spawn_captures_command_and_trailing_args() {
        // Regression test: --spawn must take everything after the command
        // as args, and stop parsing flags (they belong to the child).
        let args = argv(&["--spawn", "myprog", "--leak-check", "--foo", "bar"]);
        let parsed = parse_ci_args(&args).unwrap();
        match parsed.target {
            CiTarget::Spawn { command, args } => {
                assert_eq!(command, "myprog");
                assert_eq!(args, vec!["--leak-check", "--foo", "bar"]);
            }
            _ => panic!("expected Spawn target"),
        }
        // Flags after --spawn's command must NOT be interpreted as mvis's
        // own flags (that was the old consuming-all-remaining-args bug).
        assert!(!parsed.leak_check);
    }

    #[test]
    fn spawn_with_no_trailing_args() {
        let args = argv(&["--spawn", "myprog"]);
        let parsed = parse_ci_args(&args).unwrap();
        match parsed.target {
            CiTarget::Spawn { command, args } => {
                assert_eq!(command, "myprog");
                assert!(args.is_empty());
            }
            _ => panic!("expected Spawn target"),
        }
    }

    #[test]
    fn spawn_missing_command_errors() {
        let args = argv(&["--spawn"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn format_json_parses() {
        let args = argv(&["--format", "json"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert!(matches!(parsed.format, Some(FormatType::Json)));
    }

    #[test]
    fn format_csv_parses() {
        let args = argv(&["--format", "csv"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert!(matches!(parsed.format, Some(FormatType::CSV)));
    }

    #[test]
    fn format_junit_parses() {
        let args = argv(&["--format", "junit"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert!(matches!(parsed.format, Some(FormatType::Junit)));
    }

    #[test]
    fn format_unknown_value_errors() {
        let args = argv(&["--format", "yaml"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn format_missing_value_errors_and_does_not_hang() {
        // Regression test for the old bug where a missing --format value
        // never advanced the index (infinite loop).
        let args = argv(&["--format"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn output_path_parses() {
        let args = argv(&["--output", "report.xml"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.output, Some("report.xml".to_string()));
    }

    #[test]
    fn growth_rate_parses() {
        let args = argv(&["--growth-rate", "1024"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.growth_rate, Some(1024));
    }

    #[test]
    fn growth_rate_rejects_non_numeric() {
        let args = argv(&["--growth-rate", "fast"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn sample_interval_parses_positive_value() {
        let args = argv(&["--sample-interval", "250"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.sample_interval, Some(250));
    }

    #[test]
    fn sample_interval_rejects_zero() {
        let args = argv(&["--sample-interval", "0"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn sample_interval_rejects_negative_and_non_numeric() {
        let args = argv(&["--sample-interval", "-5"]);
        assert!(parse_ci_args(&args).is_err());

        let args2 = argv(&["--sample-interval", "soon"]);
        assert!(parse_ci_args(&args2).is_err());
    }

    #[test]
    fn sample_interval_missing_value_errors() {
        let args = argv(&["--sample-interval"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn bare_word_becomes_attach_name_target() {
        let args = argv(&["my-process"]);
        let parsed = parse_ci_args(&args).unwrap();
        match parsed.target {
            CiTarget::AttachName(name) => assert_eq!(name, "my-process"),
            _ => panic!("expected AttachName target"),
        }
    }

    #[test]
    fn no_target_defaults_to_empty_attach_name() {
        let args = argv(&["--leak-check"]);
        let parsed = parse_ci_args(&args).unwrap();
        match parsed.target {
            CiTarget::AttachName(name) => assert_eq!(name, ""),
            _ => panic!("expected default empty AttachName target"),
        }
    }

    #[test]
    fn second_bare_word_after_target_errors() {
        // Once a target is set, another unrecognized bare word should be an
        // unknown-argument error, not silently accepted as a second target.
        let args = argv(&["my-process", "another-name"]);
        assert!(parse_ci_args(&args).is_err());
    }
    #[test]
    fn warmup_parses_positive_value() {
        let args = argv(&["--warmup", "3"]);
        let parsed = parse_ci_args(&args).unwrap();
        assert_eq!(parsed.warm_up, Some(3));
    }

    #[test]
    fn warmup_rejects_zero() {
        let args = argv(&["--warmup", "0"]);
        assert!(parse_ci_args(&args).is_err());
    }
    #[test]
    fn warmup_missing_value_errors_and_does_not_hang() {
        let args = argv(&["--warmup"]);
        assert!(parse_ci_args(&args).is_err());
    }

    #[test]
    fn combined_flags_all_populate_correctly() {
        let args = argv(&[
            "--pid",
            "99",
            "--leak-check",
            "--diff-only",
            "--max-memory",
            "128",
            "--duration",
            "10",
            "--format",
            "junit",
            "--output",
            "out.xml",
            "--growth-rate",
            "2048",
            "--sample-interval",
            "500",
        ]);
        let parsed = parse_ci_args(&args).unwrap();
        assert!(matches!(parsed.target, CiTarget::AttachPid(99)));
        assert!(parsed.leak_check);
        assert!(parsed.diff_only);
        assert_eq!(parsed.max_memory, Some(128 * 1024 * 1024));
        assert_eq!(parsed.duration, Some(Duration::from_secs(10)));
        assert!(matches!(parsed.format, Some(FormatType::Junit)));
        assert_eq!(parsed.output, Some("out.xml".to_string()));
        assert_eq!(parsed.growth_rate, Some(2048));
        assert_eq!(parsed.sample_interval, Some(500));
    }
}
