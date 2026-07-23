use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn test_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .arg("--help")
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Privacy File Guard"), "Help output should contain app description");
    assert!(stdout.contains("scan"), "Help output should list scan subcommand");
}

#[test]
fn test_cli_scan_text() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(&["scan", "fixtures/images/sample.jpg"])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg scan should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Privacy File Guard Scan Report"));
    assert!(stdout.contains("sample.jpg"));
    assert!(stdout.contains("jpeg"));
}

#[test]
fn test_cli_scan_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(&["scan", "fixtures/images/sample.jpg", "--format", "json"])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg scan --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Stdout should be valid JSON");
    assert_eq!(parsed["detected_format"], "jpeg");
    assert_eq!(parsed["input"]["name"], "sample.jpg");
}

#[test]
fn test_cli_scan_report() {
    let report_path = "/tmp/pfg_report.json";
    let _ = fs::remove_file(report_path);

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(&["scan", "fixtures/images/sample.jpg", "--report", report_path])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg scan --report should succeed");
    assert!(fs::metadata(report_path).is_ok(), "Report file should be created");

    let report_contents = fs::read_to_string(report_path).expect("Report file should be readable");
    let parsed: serde_json::Value = serde_json::from_str(&report_contents).expect("Report should be valid JSON");
    assert_eq!(parsed["detected_format"], "jpeg");

    let _ = fs::remove_file(report_path);
}

#[test]
fn test_cli_scan_fail_on() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(&["scan", "fixtures/images/sample.jpg", "--fail-on", "low"])
        .output()
        .expect("Failed to execute pfg binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "pfg scan --fail-on low should return exit code 1 when findings meet or exceed threshold"
    );
}
