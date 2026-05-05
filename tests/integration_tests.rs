//! Integration tests for mvis CLI
//!
//! These tests verify end-to-end functionality of the CLI commands.
//! Some tests require elevated privileges (marked with #[ignore]).

use std::process::Command;
use std::fs;
use std::path::Path;

/// Helper to run mvis command
fn run_mvis(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(&["run", "--release", "--"])
        .args(args)
        .output()
        .expect("Failed to execute mvis command")
}

/// Test that mvis list command works
#[test]
fn test_list_command() {
    let output = run_mvis(&["list"]);

    assert!(
        output.status.success(),
        "list command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should contain header
    assert!(stdout.contains("PID"), "Output missing PID header");
    assert!(stdout.contains("NAME"), "Output missing NAME header");
    assert!(stdout.contains("MEMORY"), "Output missing MEMORY header");

    // Should list at least one process (the current process)
    assert!(stdout.lines().count() > 3, "Output too short, expected process entries");
}

/// Test that mvis list with filter works
#[test]
fn test_list_command_with_filter() {
    let output = run_mvis(&["list", "cargo"]);

    assert!(
        output.status.success(),
        "list with filter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Should contain header even with filter
    assert!(stdout.contains("PID"), "Filtered output missing PID header");
}

/// Test that mvis scan command accepts valid mode flags
#[test]
#[ignore] // Requires admin/sudo and a valid process to scan
fn test_scan_command_all_mode() {
    // Get current process ID as a test target
    let pid = std::process::id();
    let pid_str = pid.to_string();

    let output = run_mvis(&["scan", &pid_str, "-a"]);

    // Should execute without crashing (even if it fails gracefully on non-admin)
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Either success, or permission error (acceptable for unprivileged execution)
    if !output.status.success() {
        assert!(
            stderr.contains("permission") || stderr.contains("admin") || stderr.contains("access"),
            "Unexpected error: {}",
            stderr
        );
    }
}

/// Test that mvis scan command with verbose mode works
#[test]
#[ignore] // Requires admin/sudo
fn test_scan_command_verbose_mode() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    let output = run_mvis(&["scan", &pid_str, "-v"]);

    // Should not crash
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        // Permission errors are acceptable
        assert!(
            stderr.contains("permission") || stderr.contains("admin"),
            "Unexpected error: {}",
            stderr
        );
    }
}

/// Test that mvis scan with JSON output produces valid JSON
#[test]
#[ignore] // Requires admin/sudo
fn test_scan_json_output() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    let output = run_mvis(&["scan", &pid_str, "-a", "-json"]);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Try to parse as JSON
        if !stdout.is_empty() {
            let result: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
            assert!(
                result.is_ok(),
                "JSON output is not valid JSON: {}",
                stdout
            );
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Permission errors are acceptable
        assert!(
            stderr.contains("permission") || stderr.contains("admin"),
            "Unexpected error: {}",
            stderr
        );
    }
}

/// Test that mvis handles invalid process names gracefully
#[test]
fn test_scan_invalid_process_name() {
    let output = run_mvis(&["scan", "nonexistent_process_xyz_12345", "-a"]);

    // Should fail gracefully, not crash
    assert!(
        !output.status.success(),
        "Should fail for nonexistent process"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") 
            || stderr.contains("No such process") 
            || stderr.contains("error"),
        "Should provide helpful error message. Got: {}",
        stderr
    );
}

/// Test that mvis handles invalid mode gracefully
#[test]
fn test_scan_invalid_mode() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    let output = run_mvis(&["scan", &pid_str, "-invalid"]);

    // Should either work (if mode is accepted) or fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Either succeeds or has meaningful error
    if !output.status.success() {
        assert!(
            !stderr.is_empty(),
            "Failed but no error message provided"
        );
    }
}

/// Test that missing required arguments produce helpful errors
#[test]
fn test_missing_required_arguments() {
    let output = run_mvis(&["scan"]);

    assert!(
        !output.status.success(),
        "Should fail when required args are missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "Should provide error message for missing arguments"
    );
}

/// Test that unknown command fails gracefully
#[test]
fn test_unknown_command() {
    let output = run_mvis(&["unknowncmd"]);

    assert!(!output.status.success(), "Should fail for unknown command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "Should provide error message for unknown command"
    );
}

/// Test that leak detection command accepts valid arguments
#[test]
#[ignore] // Requires admin/sudo and a process that might leak
fn test_leak_command_valid_args() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    // Use short timeout (1 second) to keep test fast
    let output = run_mvis(&["leak", &pid_str, "1"]);

    // Either succeeds or has permission error
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        assert!(
            stderr.contains("permission") 
                || stderr.contains("admin") 
                || stderr.contains("ptrace"),
            "Unexpected error: {}",
            stderr
        );
    }
}

/// Test that leak detection rejects invalid interval
#[test]
fn test_leak_command_invalid_interval() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    let output = run_mvis(&["leak", &pid_str, "not_a_number"]);

    assert!(!output.status.success(), "Should fail for invalid interval");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.is_empty(),
        "Should provide error for invalid interval"
    );
}

/// Test that multi-sample leak detection works
#[test]
#[ignore] // Requires admin/sudo
fn test_leak_m_command_valid_args() {
    let pid = std::process::id();
    let pid_str = pid.to_string();

    // Short interval and few samples to keep test fast
    let output = run_mvis(&["leak-m", &pid_str, "1", "2"]);

    // Either succeeds or has permission error
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        assert!(
            stderr.contains("permission") 
                || stderr.contains("admin") 
                || stderr.contains("ptrace"),
            "Unexpected error: {}",
            stderr
        );
    }
}

/// Test JSON export file creation (if supported)
#[test]
#[ignore] // Requires admin/sudo
fn test_scan_json_export_file() {
    let pid = std::process::id();
    let pid_str = pid.to_string();
    let export_file = "/tmp/mvis_test_export.json";

    // Clean up any existing file
    let _ = fs::remove_file(export_file);

    let output = run_mvis(&["scan", &pid_str, "-a", "-json", export_file]);

    if output.status.success() {
        // Check if file was created
        if Path::new(export_file).exists() {
            let content = fs::read_to_string(export_file)
                .expect("Failed to read exported file");
            
            // Verify it's valid JSON
            let result: Result<serde_json::Value, _> = serde_json::from_str(&content);
            assert!(result.is_ok(), "Exported file is not valid JSON");
            
            // Clean up
            let _ = fs::remove_file(export_file);
        }
    }
}
