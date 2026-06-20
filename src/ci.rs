use crate::utils::error::AppError;
use crate::utils::process::{FuzzyMatch, fuzzy_find_pid};
use std::process::{Child, Command};
use std::time::Duration;

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
}

pub fn ci_main(args: &[String]) -> i32 {
    let parsed: CiArgs = match parse_ci_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };

    let (pid, child) = match resolve_target(&parsed.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}", e);
            return 1;
        }
    };
    todo!()
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
    todo!()
}
