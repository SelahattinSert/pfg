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
    assert!(
        stdout.contains("Privacy File Guard"),
        "Help output should contain app description"
    );
    assert!(
        stdout.contains("scan"),
        "Help output should list scan subcommand"
    );
}

#[test]
fn test_cli_scan_text() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(["scan", "fixtures/images/sample.jpg"])
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
        .args(["scan", "fixtures/images/sample.jpg", "--format", "json"])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(
        output.status.success(),
        "pfg scan --format json should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout should be valid JSON");
    assert_eq!(parsed["detected_format"], "jpeg");
    assert_eq!(parsed["input"]["display_name"], "sample.jpg");
}

#[test]
fn test_cli_scan_report() {
    let report_path = "/tmp/pfg_report.json";
    let _ = fs::remove_file(report_path);

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "scan",
            "fixtures/images/sample.jpg",
            "--report",
            report_path,
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg scan --report should succeed");
    assert!(
        fs::metadata(report_path).is_ok(),
        "Report file should be created"
    );

    let report_contents = fs::read_to_string(report_path).expect("Report file should be readable");
    let parsed: serde_json::Value =
        serde_json::from_str(&report_contents).expect("Report should be valid JSON");
    assert_eq!(parsed["detected_format"], "jpeg");

    let _ = fs::remove_file(report_path);
}

#[test]
fn test_cli_scan_fail_on() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(["scan", "fixtures/images/sample.jpg", "--fail-on", "low"])
        .output()
        .expect("Failed to execute pfg binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "pfg scan --fail-on low should return exit code 1 when findings meet or exceed threshold"
    );
}

#[test]
fn test_cli_clean_default() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_clean_default");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/images/sample.jpg",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(output.status.success(), "pfg clean should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Clean Report") || stdout.contains("Clean Summary"));

    let cleaned_file = temp_dir.join("sample.pfg.jpg");
    assert!(
        cleaned_file.exists(),
        "Cleaned output file should be created"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_clean_strict() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_clean_strict");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/images/sample.jpg",
            "--profile",
            "strict",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(
        output.status.success(),
        "pfg clean --profile strict should succeed"
    );

    let cleaned_file = temp_dir.join("sample.pfg.jpg");
    assert!(
        cleaned_file.exists(),
        "Cleaned output file should be created with strict profile"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_clean_safe_name() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_clean_safe_name");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/images/sample.jpg",
            "--safe-name",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(
        output.status.success(),
        "pfg clean --safe-name should succeed"
    );

    let entries: Vec<_> = fs::read_dir(&temp_dir)
        .unwrap()
        .map(|r| r.unwrap().file_name().to_string_lossy().to_string())
        .collect();

    assert_eq!(entries.len(), 1, "Should create 1 file in output directory");
    assert!(
        entries[0].ends_with(".jpg") && entries[0] != "sample.pfg.jpg",
        "Filename should be hash-based safe name, found: {}",
        entries[0]
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_verify_clean() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_verify_clean");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let clean_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/images/sample.jpg",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg clean");
    assert!(clean_output.status.success());

    let cleaned_file = temp_dir.join("sample.pfg.jpg");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "verify",
            "fixtures/images/sample.jpg",
            cleaned_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg verify");

    assert_eq!(
        verify_output.status.code(),
        Some(0),
        "pfg verify on clean file should exit with code 0"
    );
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(stdout.contains("Verification Report"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_verify_fail() {
    let verify_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "verify",
            "fixtures/images/sample.jpg",
            "fixtures/images/sample.jpg",
        ])
        .output()
        .expect("Failed to execute pfg verify");

    assert_eq!(
        verify_output.status.code(),
        Some(6),
        "pfg verify on uncleaned file should exit with code 6"
    );
}

#[test]
fn test_cli_pdf_scan() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(["scan", "fixtures/pdf/sample.pdf", "--format", "json"])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(
        output.status.success(),
        "pfg scan fixtures/pdf/sample.pdf should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout should be valid JSON");
    assert_eq!(parsed["detected_format"], "pdf");
    assert!(
        parsed["findings"].as_array().map_or(0, |f| f.len()) > 0,
        "Scan output should contain findings"
    );
}

#[test]
fn test_cli_pdf_clean() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_pdf_clean");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/pdf/sample.pdf",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "pfg clean should exit with code 0"
    );

    let cleaned_file = temp_dir.join("sample.pfg.pdf");
    assert!(
        cleaned_file.exists(),
        "Cleaned output PDF file should be created"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_pdf_verify() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_pdf_verify");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let clean_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/pdf/sample.pdf",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg clean");
    assert!(clean_output.status.success());

    let cleaned_file = temp_dir.join("sample.pfg.pdf");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "verify",
            "fixtures/pdf/sample.pdf",
            cleaned_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg verify");

    assert_eq!(
        verify_output.status.code(),
        Some(0),
        "pfg verify on original vs cleaned PDF should exit with code 0"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_office_scan() {
    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args(["scan", "fixtures/office/sample.docx", "--format", "json"])
        .output()
        .expect("Failed to execute pfg binary");

    assert!(
        output.status.success(),
        "pfg scan fixtures/office/sample.docx should succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout should be valid JSON");
    assert_eq!(parsed["detected_format"], "docx");
    assert!(
        parsed["findings"].as_array().map_or(0, |f| f.len()) > 0,
        "Scan output should contain findings"
    );
}

#[test]
fn test_cli_office_clean() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_office_clean");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/office/sample.docx",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "pfg clean should exit with code 0"
    );

    let cleaned_file = temp_dir.join("sample.pfg.docx");
    assert!(
        cleaned_file.exists(),
        "Cleaned output DOCX file should be created"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_office_verify() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_test_office_verify");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let clean_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "clean",
            "fixtures/office/sample.docx",
            "-o",
            temp_dir.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg clean");
    assert!(clean_output.status.success());

    let cleaned_file = temp_dir.join("sample.pfg.docx");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .args([
            "verify",
            "fixtures/office/sample.docx",
            cleaned_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute pfg verify");

    assert_eq!(
        verify_output.status.code(),
        Some(0),
        "pfg verify on original vs cleaned DOCX should exit with code 0"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_batch_scan_directory() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_batch_scan_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::copy(
        get_workspace_root().join("fixtures/images/sample.jpg"),
        temp_dir.join("sample.jpg"),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .arg("scan")
        .arg(&temp_dir)
        .arg("-r")
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Files Scanned:"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_batch_clean_directory() {
    let temp_dir = std::env::temp_dir().join("pfg_cli_batch_clean_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    fs::copy(
        get_workspace_root().join("fixtures/images/sample.jpg"),
        temp_dir.join("sample.jpg"),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_pfg"))
        .current_dir(get_workspace_root())
        .arg("clean")
        .arg(&temp_dir)
        .arg("-r")
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Cleaned Files:"));

    let _ = fs::remove_dir_all(&temp_dir);
}
