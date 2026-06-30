use std::path::PathBuf;
use std::process::Command;

fn mvis() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mvis"))
}

fn leak_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("test_programs")
        .join("leak_test_c.exe")
}

#[test]
fn growth_rate_breach_exits_2() {
    let status = mvis()
        .args(["ci", "--growth-rate", "5120", "--duration", "10",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn growth_rate_within_limit_exits_0() {
    let status = mvis()
        .args(["ci", "--growth-rate", "3145728", "--duration", "5",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn max_memory_breach_exits_2() {
    let status = mvis()
        .args(["ci", "--max-memory", "10", "--duration", "30",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

#[test]
fn duration_elapsed_exits_0() {
    let status = mvis()
        .args(["ci", "--duration", "3",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test]
fn missing_spawn_target_exits_1() {
    let status = mvis()
        .args(["ci", "--spawn"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn invalid_growth_rate_exits_1() {
    let status = mvis()
        .args(["ci", "--growth-rate", "notanumber", "--duration", "3",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}

#[test]
fn invalid_format_exits_1() {
    let status = mvis()
        .args(["ci", "--format", "xml", "--duration", "3",
               "--spawn", leak_binary().to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}