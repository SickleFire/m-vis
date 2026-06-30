use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src = PathBuf::from("tests/test_programs/leak_test_c.c");
    let out = PathBuf::from("tests/test_programs/leak_test_c.exe");

    if !out.exists() {
        let status = Command::new("gcc")
            .args([src.to_str().unwrap(), "-o", out.to_str().unwrap()])
            .status()
            .expect("gcc not found");

        assert!(status.success(), "failed to compile leak_test_c.c");
    }
}
